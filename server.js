const WebSocket = require('ws');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid'); // Vous devrez installer ce package: npm install uuid

// Modification pour permettre à Fly.io de définir le port
const PORT = process.env.PORT || 8080;

// Création du serveur HTTP pour attacher le serveur WebSocket
const server = require('http').createServer();
const wss = new WebSocket.Server({ server });

const db = new sqlite3.Database(':memory:');

// Initialisation de la base de données
db.serialize(() => {
  db.run('CREATE TABLE players (username TEXT PRIMARY KEY, score INTEGER)');
});

const players = new Map(); // Stocke les joueurs connectés
const playerModes = new Map(); // Stocke le mode de jeu de chaque joueur
const quickMatchQueue = []; // File d'attente pour les parties rapides
const privateGames = new Map(); // Stocke les parties privées
const matches = new Map(); // Stocke les matchs en cours

wss.on('connection', (ws) => {
  let currentPlayer = null;

  ws.on('message', (message) => {
    let data;
    try {
    data = JSON.parse(message);
    } catch (err) {
    console.error('Données malformées reçues :', message);
    return;
    }

    if (data.type === 'login') {
    currentPlayer = data.username;
    
    // Vérifier si le joueur existe déjà
    if (players.has(currentPlayer)) {
    ws.send(JSON.stringify({ 
    type: 'login_error', 
    message: 'Ce pseudo est déjà utilisé. Veuillez en choisir un autre.' 
    }));
    return;
    }
    
    players.set(currentPlayer, { ws, choice: null });
    console.log(`Joueur connecté : ${currentPlayer}`);

    // Ajouter le joueur à la base de données s'il n'existe pas
    db.get('SELECT score FROM players WHERE username = ?', [currentPlayer], (err, row) => {
    if (err) {
    console.error('Erreur lors de la récupération du joueur :', err);
    return;
    }
    if (!row) {
    db.run('INSERT INTO players (username, score) VALUES (?, ?)', [currentPlayer, 0], (err) => {
    if (err) {
    console.error('Erreur lors de l\'insertion du joueur :', err);
    }
    });
    }
    });

    // Informer le client que la connexion est réussie
    ws.send(JSON.stringify({ type: 'login_success' }));
    
    // Envoyer le classement au nouveau joueur
    broadcastRanking();
    
    // Mettre à jour le nombre de joueurs en ligne pour tous les joueurs
    broadcastOnlineCount();
    
    } else if (data.type === 'select_mode') {
    playerModes.set(currentPlayer, data.mode);
    console.log(`${currentPlayer} a sélectionné le mode: ${data.mode}`);
    
    } else if (data.type === 'play_ai') {
    if (!['pierre', 'feuille', 'ciseaux'].includes(data.choice)) {
    console.error('Choix invalide reçu :', data.choice);
    return;
    }
    
    const playerChoice = data.choice;
    const aiChoice = getRandomChoice();
    const result = getResult(playerChoice, aiChoice);
    
    let resultMessage, resultType;
    
    if (result === 'draw') {
    resultMessage = `Égalité ! (${playerChoice} contre ${aiChoice})`;
    resultType = 'draw';
    } else if (result === 'player1') {
    resultMessage = `Vous avez gagné ! (${playerChoice} bat ${aiChoice})`;
    resultType = 'player';
    // Mettre à jour le score dans la base de données
    db.run('UPDATE players SET score = score + 1 WHERE username = ?', [currentPlayer]);
    } else {
    resultMessage = `Vous avez perdu ! (${aiChoice} bat ${playerChoice})`;
    resultType = 'ai';
    }
    
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'ai_result', 
    message: resultMessage,
    result: resultType,
    playerChoice,
    aiChoice
    }));
    
    // Mettre à jour le classement
    broadcastRanking();
    
    } else if (data.type === 'quick_match') {
    // Ajouter le joueur à la file d'attente pour une partie rapide
    if (!quickMatchQueue.includes(currentPlayer)) {
    quickMatchQueue.push(currentPlayer);
    console.log(`${currentPlayer} a rejoint la file d'attente pour une partie rapide`);
    }
    
    // Essayer de créer un match
    matchQuickPlayers();
    
    } else if (data.type === 'create_private_game') {
    // Créer un ID unique pour la partie privée
    const gameId = uuidv4();
    privateGames.set(gameId, { host: currentPlayer, guest: null });
    console.log(`${currentPlayer} a créé une partie privée avec l'ID: ${gameId}`);
    
    // Informer le client de l'ID de la partie
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'private_game_created', 
    gameId 
    }));
    
    } else if (data.type === 'join_private_game') {
    const gameId = data.gameId;
    const game = privateGames.get(gameId);
    
    if (!game) {
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'error', 
    message: 'Cette partie privée n\'existe pas ou a été fermée.' 
    }));
    return;
    }
    
    if (game.host === currentPlayer) {
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'error', 
    message: 'Vous ne pouvez pas rejoindre votre propre partie.' 
    }));
    return;
    }
    
    if (game.guest) {
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'error', 
    message: 'Cette partie privée est déjà complète.' 
    }));
    return;
    }
    
    // Rejoindre la partie
    game.guest = currentPlayer;
    console.log(`${currentPlayer} a rejoint la partie privée de ${game.host}`);
    
    // Créer le match
    matches.set(game.host, currentPlayer);
    matches.set(currentPlayer, game.host);
    
    // Informer les deux joueurs
    players.get(game.host).ws.send(JSON.stringify({ 
    type: 'game_joined', 
    opponent: currentPlayer 
    }));
    
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'game_joined', 
    opponent: game.host 
    }));
    
    } else if (data.type === 'play_online') {
    if (!['pierre', 'feuille', 'ciseaux'].includes(data.choice)) {
    console.error('Choix invalide reçu :', data.choice);
    return;
    }
    
    if (players.has(currentPlayer)) {
    players.get(currentPlayer).choice = data.choice;
    console.log(`Joueur ${currentPlayer} a choisi : ${data.choice}`);
    
    const opponent = matches.get(currentPlayer);
    if (opponent && players.has(opponent)) {
    const opponentChoice = players.get(opponent).choice;
    
    if (opponentChoice) {
    const result = getResult(data.choice, opponentChoice);
    
    if (result === 'draw') {
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'game_result', 
    message: `Égalité ! (${data.choice} contre ${opponentChoice})`,
    result: 'draw'
    }));
    
    players.get(opponent).ws.send(JSON.stringify({ 
    type: 'game_result', 
    message: `Égalité ! (${opponentChoice} contre ${data.choice})`,
    result: 'draw'
    }));
    } else if (result === 'player1') {
    db.run('UPDATE players SET score = score + 1 WHERE username = ?', [currentPlayer]);
    
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'game_result', 
    message: `Vous avez gagné ! (${data.choice} bat ${opponentChoice})`,
    result: 'player'
    }));
    
    players.get(opponent).ws.send(JSON.stringify({ 
    type: 'game_result', 
    message: `Vous avez perdu ! (${data.choice} bat ${opponentChoice})`,
    result: 'opponent'
    }));
    } else {
    db.run('UPDATE players SET score = score + 1 WHERE username = ?', [opponent]);
    
    players.get(currentPlayer).ws.send(JSON.stringify({ 
    type: 'game_result', 
    message: `Vous avez perdu ! (${opponentChoice} bat ${data.choice})`,
    result: 'opponent'
    }));
    
    players.get(opponent).ws.send(JSON.stringify({ 
    type: 'game_result', 
    message: `Vous avez gagné ! (${opponentChoice} bat ${data.choice})`,
    result: 'player'
    }));
    }
    
    // Réinitialiser les choix pour un nouveau tour
    players.get(currentPlayer).choice = null;
    players.get(opponent).choice = null;
    
    // Mettre à jour le classement
    broadcastRanking();
    }
    }
    }
    } else if (data.type === 'leave_game') {
    const opponent = matches.get(currentPlayer);
    
    if (opponent && opponent !== 'IA' && players.has(opponent)) {
    players.get(opponent).ws.send(JSON.stringify({ 
    type: 'opponent_left', 
    message: 'Votre adversaire a quitté la partie.' 
    }));
    }
    
    // Supprimer le match
    removePlayerFromMatch(currentPlayer);
    
    // Supprimer le joueur de la file d'attente
    const queueIndex = quickMatchQueue.indexOf(currentPlayer);
    if (queueIndex !== -1) {
    quickMatchQueue.splice(queueIndex, 1);
    }
    
    // Supprimer les parties privées où le joueur est l'hôte
    for (const [gameId, game] of privateGames.entries()) {
    if (game.host === currentPlayer) {
    privateGames.delete(gameId);
    }
    }
    }
  });

  ws.on('close', () => {
    if (currentPlayer) {
    const opponent = matches.get(currentPlayer);
    if (opponent && opponent !== 'IA' && players.has(opponent)) {
    players.get(opponent).ws.send(JSON.stringify({ 
    type: 'opponent_left', 
    message: 'Votre adversaire a quitté la partie.' 
    }));
    }
    
    // Supprimer le joueur des structures de données
    players.delete(currentPlayer);
    playerModes.delete(currentPlayer);
    removePlayerFromMatch(currentPlayer);
    
    // Supprimer le joueur de la file d'attente
    const queueIndex = quickMatchQueue.indexOf(currentPlayer);
    if (queueIndex !== -1) {
    quickMatchQueue.splice(queueIndex, 1);
    }
    
    // Supprimer les parties privées où le joueur est l'hôte
    for (const [gameId, game] of privateGames.entries()) {
    if (game.host === currentPlayer) {
    privateGames.delete(gameId);
    }
    }
    
    console.log(`Joueur déconnecté : ${currentPlayer}`);
    
    // Mettre à jour le nombre de joueurs en ligne
    broadcastOnlineCount();
    }
  });
});

function matchQuickPlayers() {
  console.log('Tentative d\'association des joueurs en attente de partie rapide...');
  console.log('Joueurs en attente :', quickMatchQueue);
  
  while (quickMatchQueue.length >= 2) {
    const player1 = quickMatchQueue.shift();
    const player2 = quickMatchQueue.shift();
    
    if (players.has(player1) && players.has(player2)) {
    matches.set(player1, player2);
    matches.set(player2, player1);
    
    console.log(`Match rapide créé : ${player1} vs ${player2}`);
    
    players.get(player1).ws.send(JSON.stringify({ 
    type: 'game_joined', 
    opponent: player2 
    }));
    
    players.get(player2).ws.send(JSON.stringify({ 
    type: 'game_joined', 
    opponent: player1 
    }));
    }
  }
}

function removePlayerFromMatch(player) {
  const opponent = matches.get(player);
  if (opponent) {
    matches.delete(player);
    if (opponent !== 'IA') {
    matches.delete(opponent);
    }
  }
}

function getResult(choice1, choice2) {
  if (choice1 === choice2) return 'draw';
  if (
    (choice1 === 'pierre' && choice2 === 'ciseaux') ||
    (choice1 === 'feuille' && choice2 === 'pierre') ||
    (choice1 === 'ciseaux' && choice2 === 'feuille')
  ) {
    return 'player1';
  }
  return 'player2';
}

function getRandomChoice() {
  const choices = ['pierre', 'feuille', 'ciseaux'];
  return choices[Math.floor(Math.random() * choices.length)];
}

function broadcastRanking() {
  db.all('SELECT username, score FROM players ORDER BY score DESC', (err, rows) => {
    if (err) {
    console.error('Erreur lors de la récupération du classement :', err);
    return;
    }
    
    const ranking = rows.map((row) => ({ username: row.username, score: row.score }));
    const rankingData = JSON.stringify({ type: 'ranking', ranking });
    
    players.forEach((player) => {
    player.ws.send(rankingData);
    });
  });
}

function broadcastOnlineCount() {
  const count = players.size;
  const countData = JSON.stringify({ type: 'online_count', count });
  
  players.forEach((player) => {
    player.ws.send(countData);
  });
}

// Gestion des erreurs du serveur WebSocket
wss.on('error', (error) => {
  console.error('Erreur du serveur WebSocket :', error);
});

// Démarrage du serveur sur le port défini par Fly.io ou 8080 par défaut
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Serveur WebSocket démarré sur le port ${PORT}`);
});