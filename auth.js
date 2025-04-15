// auth.js - Gestion de l'authentification et des comptes utilisateurs

const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt"); // Vous devrez installer ce package: npm install bcrypt
const jwt = require("jsonwebtoken"); // Vous devrez installer ce package: npm install jsonwebtoken
const { v4: uuidv4 } = require("uuid");

// Configuration
const JWT_SECRET = process.env.JWT_SECRET || "votre_clé_secrète_jwt"; // À changer en production
const SALT_ROUNDS = 10;
const TOKEN_EXPIRY = '7d'; // Durée de validité du token

// Initialisation de la base de données
const db = new sqlite3.Database("./database.sqlite");

// Création des tables nécessaires
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

  // Déconnexion d'un utilisateur
  async logout(token) {
    return new Promise((resolve, reject) => {
      db.run("DELETE FROM sessions WHERE token = ?", [token], (err) => {
        if (err) return reject({ status: 500, message: "Erreur lors de la déconnexion", error: err });
        resolve({ status: 200, message: "Déconnexion réussie" });
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
        db.get("SELECT user_id FROM sessions WHERE token = ? AND expires_at > CURRENT_TIMESTAMP", [token], (err, session) => {
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

  // Nettoyage des sessions expirées
  cleanExpiredSessions() {
    db.run("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP");
  }
}

// Middleware pour vérifier l'authentification
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: "Authentification requise" });
  }
  
  const authManager = new AuthManager();
  authManager.verifyToken(token)
    .then(result => {
      req.user = result.data;
      next();
    })
    .catch(error => {
      res.status(error.status || 401).json({ message: error.message });
    });
}

// Nettoyer les sessions expirées périodiquement
setInterval(() => {
  const authManager = new AuthManager();
  authManager.cleanExpiredSessions();
}, 24 * 60 * 60 * 1000); // Une fois par jour

// Exporter les fonctionnalités
module.exports = {
  AuthManager,
  authMiddleware
};