const WebSocket = require("ws");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcrypt"); // Vous devrez installer ce package: npm install bcrypt
const jwt = require("jsonwebtoken"); // Vous devrez installer ce package: npm install jsonwebtoken

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || "votre_clé_secrète_jwt"; // À changer en production
const SALT_ROUNDS = 10;
const TOKEN_EXPIRY = '7d'; // Durée de validité du token

// Configuration du serveur WebSocket
const wss = new WebSocket.Server({
  port: process.env.PORT || 8080,
  // Permettre les connexions depuis n'importe quelle origine
  perMessageDeflate: {
    zlibDeflateOptions: {
      chunkSize: 1024,
      memLevel: 7,
      level: 3,
    },
    zlibInflateOptions: {
      chunkSize: 10 * 1024,
    },
    clientNoContextTakeover: true,
    serverNoContextTakeover: true,
    serverMaxWindowBits: 10,
    concurrencyLimit: 10,
    threshold: 1024,
  },
});

// Initialisation de la base de données
const db = new sqlite3.Database("./database.sqlite");

// Initialisation des tables
db.serialize(() => {
  // Table des utilisateurs
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
  )`);

  // Table des sessions
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT,
    expires_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // Table des scores
  db.run("CREATE TABLE IF NOT EXISTS players (username TEXT PRIMARY KEY, score INTEGER)");
});

// Classe pour gérer l'authentification
class AuthManager {
  // Inscription d'un nouvel utilisateur
  async register(username, email, password) {
    return new Promise((resolve, reject) => {
      // Vérifier si l'utilisateur existe déjà
      db.get("SELECT id FROM users WHERE username = ? OR email = ?", [username, email], async (err, row) => {
        if (err) return reject({ status: 500, message: "Erreur de base de données", error: err });
        if (row) return reject({ status: 409, message: "Nom d'utilisateur ou email déjà utilisé" });

        try {
          // Hachage du mot de passe
          const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
          const userId = uuidv4();

          // Insertion du nouvel utilisateur
          db.run(
            "INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)",
            [userId, username, email, hashedPassword],
            (err) => {
              if (err) return reject({ status: 500, message: "Erreur lors de la création du compte", error: err });
              
              // Création du token JWT
              const token = this.generateToken(userId, username);
              
              // Enregistrement de la session
              this.saveSession(token, userId);
              
              // Ajouter l'utilisateur à la table des scores
              db.run("INSERT INTO players (username, score) VALUES (?, ?)", [username, 0]);
              
              resolve({ 
                status: 201, 
                message: "Compte créé avec succès", 
                data: { 
                  userId, 
                  username, 
                  token 
                } 
              });
            }
          );
        } catch (error) {
          reject({ status: 500, message: "Erreur lors du hachage du mot de passe", error });
        }
      });
    });
  }

  // Connexion d'un utilisateur
  async login(username, password) {
    return new Promise((resolve, reject) => {
      db.get("SELECT id, username, password FROM users WHERE username = ?", [username], async (err, user) => {
        if (err) return reject({ status: 500, message: "Erreur de base de données", error: err });
        if (!user) return reject({ status: 401, message: "Nom d'utilisateur ou mot de passe incorrect" });

        try {
          // Vérification du mot de passe
          const match = await bcrypt.compare(password, user.password);
          if (!match) return reject({ status: 401, message: "Nom d'utilisateur ou mot de passe incorrect" });

          // Mise à jour de la date de dernière connexion
          db.run("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", [user.id]);

          // Création du token JWT
          const token = this.generateToken(user.id, user.username);
          
          // Enregistrement de la session
          this.saveSession(token, user.id);
          
          resolve({ 
            status: 200, 
            message: "Connexion réussie", 
            data: { 
              userId: user.id, 
              username: user.username, 
              token 
            } 
          });
        } catch (error) {
          reject({ status: 500, message: "Erreur lors de la vérification du mot de passe", error });
        }
      });
    });
  }

  // Vérification d'un token
  async verifyToken(token) {
    return new Promise((resolve, reject) => {
      try {
        // Vérifier si le token est valide
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Vérifier si la session existe toujours
        db.get("SELECT user_id FROM sessions WHERE token = ? AND expires_at > datetime('now')", [token], (err, session) => {
          if (err) return reject({ status: 500, message: "Erreur de base de données", error: err });
          if (!session) return reject({ status: 401, message: "Session expirée ou invalide" });
          
          // Récupérer les informations de l'utilisateur
          db.get("SELECT id, username FROM users WHERE id = ?", [session.user_id], (err, user) => {
            if (err) return reject({ status: 500, message: "Erreur de base de données", error: err });
            if (!user) return reject({ status: 401, message: "Utilisateur introuvable" });
            
            resolve({ 
              status: 200, 
              data: { 
                userId: user.id, 
                username: user.username 
              } 
            });
          });
        });
      } catch (error) {
        reject({ status: 401, message: "Token invalide", error });
      }
    });
  }

  // Génération d'un token JWT
  generateToken(userId, username) {
    return jwt.sign(
      { userId, username },
      JWT_SECRET,
      { expiresIn: TOKEN_EXPIRY }
    );
  }

  // Enregistrement d'une session
  saveSession(token, userId) {
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 jours de validité
    
    db.run(
      "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
      [token, userId, expiresAt.toISOString()]
    );
  }

  // Déconnexion d'un utilisateur
  async logout(token) {
    return new Promise((resolve, reject) => {
      db.run("DELETE FROM sessions WHERE token = ?", [token], (err) => {
        if (err) return reject({ status: 500, message: "Erreur lors de la déconnexion", error: err });
        resolve({ status: 200, message: "Déconnexion réussie" });
      });
    });
  }

  // Nettoyage des sessions expirées
  cleanExpiredSessions() {
    db.run("DELETE FROM sessions WHERE expires_at < datetime('now')");
  }
}

// Nettoyer les sessions expirées périodiquement
setInterval(() => {
  const authManager = new AuthManager();
  authManager.cleanExpiredSessions();
}, 24 * 60 * 60 * 1000); // Une fois par jour

const players = new Map(); // Stocke les joueurs connectés
const playerModes = new Map(); // Stocke le mode de jeu de chaque joueur
const quickMatchQueue = []; // File d'attente pour les parties rapides
const privateGames = new Map(); // Stocke les parties privées
const matches = new Map(); // Stocke les matchs en cours
const playerReadyState = new Map(); // Stocke l'état "prêt" des joueurs
const authenticatedUsers = new Map(); // Stocke les utilisateurs authentifiés

wss.on("connection", (ws) => {
  let currentPlayer = null;
  let currentUserId = null;
  let currentToken = null;

  ws.on("message", async (message) => {
    let data;
    try {
      data = JSON.parse(message);
    } catch (err) {
      console.error("Données malformées reçues :", message);
      return;
    }

    // Gestion de l'authentification
    if (data.type === "register") {
      try {
        const authManager = new AuthManager();
        const result = await authManager.register(data.username, data.email, data.password);
        
        currentPlayer = result.data.username;
        currentUserId = result.data.userId;
        currentToken = result.data.token;
        
        authenticatedUsers.set(currentPlayer, { 
          userId: currentUserId, 
          token: currentToken,
          ws 
        });
        
        players.set(currentPlayer, { ws, choice: null });
        
        ws.send(JSON.stringify({ 
          type: "register_success", 
          username: currentPlayer,
          token: currentToken
        }));
        
        // Mettre à jour le nombre de joueurs en ligne
        broadcastOnlineCount();
        
        // Envoyer le classement au nouveau joueur
        broadcastRanking();
      } catch (error) {
        ws.send(JSON.stringify({ 
          type: "register_error", 
          message: error.message 
        }));
      }
    } else if (data.type === "login") {
      // Si c'est une connexion avec token
      if (data.token) {
        try {
          const authManager = new AuthManager();
          const result = await authManager.verifyToken(data.token);
          
          currentPlayer = result.data.username;
          currentUserId = result.data.userId;
          currentToken = data.token;
          
          authenticatedUsers.set(currentPlayer, { 
            userId: currentUserId, 
            token: currentToken,
            ws 
          });
          
          players.set(currentPlayer, { ws, choice: null });
          
          console.log(`Joueur connecté avec token : ${currentPlayer}`);
          
          ws.send(JSON.stringify({ 
            type: "login_success",
            username: currentPlayer
          }));
          
          // Mettre à jour le nombre de joueurs en ligne
          broadcastOnlineCount();
          
          // Envoyer le classement au joueur
          broadcastRanking();
        } catch (error) {
          ws.send(JSON.stringify({ 
            type: "login_error", 
            message: "Session expirée, veuillez vous reconnecter" 
          }));
        }
      } 
      // Connexion avec nom d'utilisateur et mot de passe
      else if (data.username && data.password) {
        try {
          const authManager = new AuthManager();
          const result = await authManager.login(data.username, data.password);
          
          currentPlayer = result.data.username;
          currentUserId = result.data.userId;
          currentToken = result.data.token;
          
          authenticatedUsers.set(currentPlayer, { 
            userId: currentUserId, 
            token: currentToken,
            ws 
          });
          
          players.set(currentPlayer, { ws, choice: null });
          
          console.log(`Joueur connecté : ${currentPlayer}`);
          
          ws.send(JSON.stringify({ 
            type: "login_success",
            username: currentPlayer,
            token: currentToken
          }));
          
          // Mettre à jour le nombre de joueurs en ligne
          broadcastOnlineCount();
          
          // Envoyer le classement au joueur
          broadcastRanking();
        } catch (error) {
          ws.send(JSON.stringify({ 
            type: "login_error", 
            message: error.message 
          }));
        }
      }
      // Connexion en mode invité (ancienne méthode)
      else {
        currentPlayer = data.username;

        // Vérifier si le joueur existe déjà
        if (players.has(currentPlayer)) {
          ws.send(
            JSON.stringify({
              type: "login_error",
              message: "Ce pseudo est déjà utilisé. Veuillez en choisir un autre.",
            })
          );
          return;
        }

        players.set(currentPlayer, { ws, choice: null });
        console.log(`Joueur invité connecté : ${currentPlayer}`);

        // Ajouter le joueur à la base de données s'il n'existe pas
        db.get(
          "SELECT score FROM players WHERE username = ?",
          [currentPlayer],
          (err, row) => {
            if (err) {
              console.error("Erreur lors de la récupération du joueur :", err);
              return;
            }
            if (!row) {
              db.run(
                "INSERT INTO players (username, score) VALUES (?, ?)",
                [currentPlayer, 0],
                (err) => {
                  if (err) {
                    console.error("Erreur lors de l'insertion du joueur :", err);
                  }
                }
              );
            }
          }
        );

        // Informer le client que la connexion est réussie
        ws.send(JSON.stringify({ type: "login_success" }));

        // Envoyer le classement au nouveau joueur
        broadcastRanking();

        // Mettre à jour le nombre de joueurs en ligne pour tous les joueurs
        broadcastOnlineCount();
      }
    } else if (data.type === "logout") {
      if (currentToken) {
        try {
          const authManager = new AuthManager();
          await authManager.logout(currentToken);
          
          authenticatedUsers.delete(currentPlayer);
          
          ws.send(JSON.stringify({ 
            type: "logout_success" 
          }));
        } catch (error) {
          ws.send(JSON.stringify({ 
            type: "logout_error", 
            message: error.message 
          }));
        }
      }
      
      // Supprimer le joueur des structures de données
      if (currentPlayer) {
        const opponent = matches.get(currentPlayer);
        if (opponent && opponent !== "IA" && players.has(opponent)) {
          players.get(opponent).ws.send(
            JSON.stringify({
              type: "opponent_left",
              message: "Votre adversaire a quitté la partie.",
            })
          );
        }

        players.delete(currentPlayer);
        playerModes.delete(currentPlayer);
        playerReadyState.delete(currentPlayer);
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

        // Mettre à jour le nombre de joueurs en ligne
        broadcastOnlineCount();
        
        currentPlayer = null;
        currentUserId = null;
        currentToken = null;
      }
    } else if (data.type === "select_mode") {
      playerModes.set(currentPlayer, data.mode);
      console.log(`${currentPlayer} a sélectionné le mode: ${data.mode}`);
    } else if (data.type === "play_ai") {
      if (!["pierre", "feuille", "ciseaux"].includes(data.choice)) {
        console.error("Choix invalide reçu :", data.choice);
        return;
      }

      const playerChoice = data.choice;
      const aiChoice = getRandomChoice();
      const result = getResult(playerChoice, aiChoice);

      let resultMessage, resultType;

      if (result === "draw") {
        resultMessage = `Égalité ! (${playerChoice} contre ${aiChoice})`;
        resultType = "draw";
      } else if (result === "player1") {
        resultMessage = `Vous avez gagné ! (${playerChoice} bat ${aiChoice})`;
        resultType = "player";
        // Mettre à jour le score dans la base de données
        db.run("UPDATE players SET score = score + 1 WHERE username = ?", [
          currentPlayer,
        ]);
      } else {
        resultMessage = `Vous avez perdu ! (${aiChoice} bat ${playerChoice})`;
        resultType = "ai";
      }

      players.get(currentPlayer).ws.send(
        JSON.stringify({
          type: "ai_result",
          message: resultMessage,
          result: resultType,
          playerChoice,
          aiChoice,
        })
      );

      // Mettre à jour le classement
      broadcastRanking();
    } else if (data.type === "quick_match") {
      // Ajouter le joueur à la file d'attente pour une partie rapide
      if (!quickMatchQueue.includes(currentPlayer)) {
        quickMatchQueue.push(currentPlayer);
        console.log(
          `${currentPlayer} a rejoint la file d'attente pour une partie rapide`
        );
      }

      // Essayer de créer un match
      matchQuickPlayers();
    } else if (data.type === "create_private_game") {
      // Créer un ID unique pour la partie privée
      const gameId = uuidv4();
      privateGames.set(gameId, { host: currentPlayer, guest: null });
      console.log(
        `${currentPlayer} a créé une partie privée avec l'ID: ${gameId}`
      );

      // Informer le client de l'ID de la partie
      players.get(currentPlayer).ws.send(
        JSON.stringify({
          type: "private_game_created",
          gameId,
        })
      );
    } else if (data.type === "join_private_game") {
      const gameId = data.gameId;
      const game = privateGames.get(gameId);

      if (!game) {
        players.get(currentPlayer).ws.send(
          JSON.stringify({
            type: "error",
            message: "Cette partie privée n'existe pas ou a été fermée.",
          })
        );
        return;
      }

      if (game.host === currentPlayer) {
        players.get(currentPlayer).ws.send(
          JSON.stringify({
            type: "error",
            message: "Vous ne pouvez pas rejoindre votre propre partie.",
          })
        );
        return;
      }

      if (game.guest) {
        players.get(currentPlayer).ws.send(
          JSON.stringify({
            type: "error",
            message: "Cette partie privée est déjà complète.",
          })
        );
        return;
      }

      // Rejoindre la partie
      game.guest = currentPlayer;
      console.log(
        `${currentPlayer} a rejoint la partie privée de ${game.host}`
      );

      // Créer le match
      matches.set(game.host, currentPlayer);
      matches.set(currentPlayer, game.host);

      // Initialiser l'état "prêt" des joueurs
      playerReadyState.set(game.host, false);
      playerReadyState.set(currentPlayer, false);

      // Informer les deux joueurs
      players.get(game.host).ws.send(
        JSON.stringify({
          type: "game_joined",
          opponent: currentPlayer,
        })
      );

      players.get(currentPlayer).ws.send(
        JSON.stringify({
          type: "game_joined",
          opponent: game.host,
        })
      );
    } else if (data.type === "play_online") {
      if (!["pierre", "feuille", "ciseaux"].includes(data.choice)) {
        console.error("Choix invalide reçu :", data.choice);
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

            if (result === "draw") {
              players.get(currentPlayer).ws.send(
                JSON.stringify({
                  type: "game_result",
                  message: `Égalité ! (${data.choice} contre ${opponentChoice})`,
                  result: "draw",
                  playerChoice: data.choice,
                  opponentChoice: opponentChoice,
                  opponentName: opponent,
                })
              );

              players.get(opponent).ws.send(
                JSON.stringify({
                  type: "game_result",
                  message: `Égalité ! (${opponentChoice} contre ${data.choice})`,
                  result: "draw",
                  playerChoice: opponentChoice,
                  opponentChoice: data.choice,
                  opponentName: currentPlayer,
                })
              );
            } else if (result === "player1") {
              db.run(
                "UPDATE players SET score = score + 1 WHERE username = ?",
                [currentPlayer]
              );

              players.get(currentPlayer).ws.send(
                JSON.stringify({
                  type: "game_result",
                  message: `Vous avez gagné ! (${data.choice} bat ${opponentChoice})`,
                  result: "player",
                  playerChoice: data.choice,
                  opponentChoice: opponentChoice,
                  opponentName: opponent,
                })
              );

              players.get(opponent).ws.send(
                JSON.stringify({
                  type: "game_result",
                  message: `Vous avez perdu ! (${data.choice} bat ${opponentChoice})`,
                  result: "opponent",
                  playerChoice: opponentChoice,
                  opponentChoice: data.choice,
                  opponentName: currentPlayer,
                })
              );
            } else {
              db.run(
                "UPDATE players SET score = score + 1 WHERE username = ?",
                [opponent]
              );

              players.get(currentPlayer).ws.send(
                JSON.stringify({
                  type: "game_result",
                  message: `Vous avez perdu ! (${opponentChoice} bat ${data.choice})`,
                  result: "opponent",
                  playerChoice: data.choice,
                  opponentChoice: opponentChoice,
                  opponentName: opponent,
                })
              );

              players.get(opponent).ws.send(
                JSON.stringify({
                  type: "game_result",
                  message: `Vous avez gagné ! (${opponentChoice} bat ${data.choice})`,
                  result: "player",
                  playerChoice: opponentChoice,
                  opponentChoice: data.choice,
                  opponentName: currentPlayer,
                })
              );
            }

            // Réinitialiser les choix pour un nouveau tour
            players.get(currentPlayer).choice = null;
            players.get(opponent).choice = null;

            // Mettre à jour le classement
            broadcastRanking();
          }
        }
      }
    } else if (data.type === "ready_for_next_round") {
      playerReadyState.set(currentPlayer, data.ready);

      const opponent = matches.get(currentPlayer);
      if (opponent && opponent !== "IA" && players.has(opponent)) {
        // Vérifier si les deux joueurs sont prêts
        if (
          playerReadyState.get(currentPlayer) &&
          playerReadyState.get(opponent)
        ) {
          // Les deux joueurs sont prêts pour le prochain tour
          players.get(currentPlayer).ws.send(
            JSON.stringify({
              type: "start_new_round",
            })
          );

          players.get(opponent).ws.send(
            JSON.stringify({
              type: "start_new_round",
            })
          );

          // Réinitialiser l'état prêt
          playerReadyState.set(currentPlayer, false);
          playerReadyState.set(opponent, false);
        } else if (
          playerReadyState.get(currentPlayer) !== playerReadyState.get(opponent)
        ) {
          // Les joueurs ont choisi des options différentes (continuer vs quitter)
          if (playerReadyState.get(currentPlayer)) {
            // Le joueur actuel veut continuer mais l'adversaire veut quitter
            players.get(currentPlayer).ws.send(
              JSON.stringify({
                type: "opponent_left",
                message: "Votre adversaire a quitté la partie.",
              })
            );
          }
          // Sinon, le joueur actuel a choisi de quitter, ce qui est géré par leaveGame()
        }
      }
    } else if (data.type === "leave_game") {
      const opponent = matches.get(currentPlayer);

      if (opponent && opponent !== "IA" && players.has(opponent)) {
        players.get(opponent).ws.send(
          JSON.stringify({
            type: "opponent_left",
            message: "Votre adversaire a quitté la partie.",
          })
        );
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

  ws.on("close", () => {
    if (currentPlayer) {
      const opponent = matches.get(currentPlayer);
      if (opponent && opponent !== "IA" && players.has(opponent)) {
        players.get(opponent).ws.send(
          JSON.stringify({
            type: "opponent_left",
            message: "Votre adversaire a quitté la partie.",
          })
        );
      }

      // Supprimer le joueur des structures de données
      players.delete(currentPlayer);
      playerModes.delete(currentPlayer);
      playerReadyState.delete(currentPlayer);
      authenticatedUsers.delete(currentPlayer);
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
  console.log(
    "Tentative d'association des joueurs en attente de partie rapide..."
  );
  console.log("Joueurs en attente :", quickMatchQueue);

  while (quickMatchQueue.length >= 2) {
    const player1 = quickMatchQueue.shift();
    const player2 = quickMatchQueue.shift();

    if (players.has(player1) && players.has(player2)) {
      matches.set(player1, player2);
      matches.set(player2, player1);

      // Initialiser l'état "prêt" des joueurs
      playerReadyState.set(player1, false);
      playerReadyState.set(player2, false);

      console.log(`Match rapide créé : ${player1} vs ${player2}`);

      players.get(player1).ws.send(
        JSON.stringify({
          type: "game_joined",
          opponent: player2,
        })
      );

      players.get(player2).ws.send(
        JSON.stringify({
          type: "game_joined",
          opponent: player1,
        })
      );
    }
  }
}

function removePlayerFromMatch(player) {
  const opponent = matches.get(player);
  if (opponent) {
    matches.delete(player);
    if (opponent !== "IA") {
      matches.delete(opponent);
    }
  }
}

function getResult(choice1, choice2) {
  if (choice1 === choice2) return "draw";
  if (
    (choice1 === "pierre" && choice2 === "ciseaux") ||
    (choice1 === "feuille" && choice2 === "pierre") ||
    (choice1 === "ciseaux" && choice2 === "feuille")
  ) {
    return "player1";
  }
  return "player2";
}

function getRandomChoice() {
  const choices = ["pierre", "feuille", "ciseaux"];
  return choices[Math.floor(Math.random() * choices.length)];
}

function broadcastRanking() {
  db.all(
    "SELECT username, score FROM players ORDER BY score DESC",
    (err, rows) => {
      if (err) {
        console.error("Erreur lors de la récupération du classement :", err);
        return;
      }

      const ranking = rows.map((row) => ({
        username: row.username,
        score: row.score,
      }));
      const rankingData = JSON.stringify({ type: "ranking", ranking });

      players.forEach((player) => {
        player.ws.send(rankingData);
      });
    }
  );
}

function broadcastOnlineCount() {
  const count = players.size;
  const countData = JSON.stringify({ type: "online_count", count });

  players.forEach((player) => {
    player.ws.send(countData);
  });
}

// Gestion des erreurs du serveur WebSocket
wss.on("error", (error) => {
  console.error("Erreur du serveur WebSocket :", error);
});

const serverPort = process.env.PORT || 8080;
console.log(`Serveur WebSocket démarré sur le port ${serverPort}`);