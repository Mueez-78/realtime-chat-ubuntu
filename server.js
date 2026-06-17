const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose(); 

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const MAX_HISTORY = 50;
const MAX_MESSAGE_LENGTH = 500;
const MAX_USERNAME_LENGTH = 24;
const RATE_LIMIT_WINDOW_MS = 3000;
const RATE_LIMIT_MAX_MESSAGES = 5;

// ==========================================
// DATABASE SETUP
// ==========================================
const db = new sqlite3.Database('./chat.db', (err) => {
  if (err) console.error('🔴 Failed to open database:', err.message);
  else console.log('📁 SQLite Database (chat.db) connected successfully.');
});

// Create table if it doesn't exist
db.run(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT,
    avatar TEXT,
    text TEXT,
    time TEXT
  )
`);

const connectedUsers = new Map(); 

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function timestamp() {
  return new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

function broadcastUserList() {
  const usernames = Array.from(connectedUsers.values()).map((u) => u.username);
  io.emit('user list', usernames);
}

// Anti-Spam System
function isRateLimited(user) {
  const now = Date.now();
  user.messageTimestamps = user.messageTimestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (user.messageTimestamps.length >= RATE_LIMIT_MAX_MESSAGES) return true;
  user.messageTimestamps.push(now);
  return false;
}

io.on('connection', (socket) => {
  console.log(`🟢 Socket connected: ${socket.id}`);

  // FETCH CHAT HISTORY FROM DATABASE
  db.all(
    `SELECT user, avatar, text, time FROM messages ORDER BY id DESC LIMIT ?`,
    [MAX_HISTORY],
    (err, rows) => {
      if (err) {
        console.error('Database read error:', err);
        return;
      }
      const history = rows.reverse();
      socket.emit('load history', history);
    }
  );

  socket.on('set username', (data) => {
    if (!data) return;

    const rawUsername = typeof data === 'string' ? data : data.name;
    if (typeof rawUsername !== 'string') return; 

    const username = rawUsername.trim().slice(0, MAX_USERNAME_LENGTH);
    if (!username || username === '[object Object]' || username === 'null') return; 

    let avatar = null;
    if (data.avatar && typeof data.avatar === 'string' && data.avatar.length < 150000) {
      avatar = data.avatar;
    }

    connectedUsers.set(socket.id, { username, avatar, messageTimestamps: [] });
    broadcastUserList();
  });

  socket.on('chat message', (data) => {
    const user = connectedUsers.get(socket.id);
    if (!user || !user.username) return; 

    if (isRateLimited(user)) {
      socket.emit('rate limited');
      return;
    }

    const text = String((data && data.text) || '').trim().slice(0, MAX_MESSAGE_LENGTH);
    if (!text) return;

    const messageData = { 
      user: user.username, 
      avatar: user.avatar,
      text, 
      time: timestamp() 
    };
    
    // SAVE NEW MESSAGE TO DATABASE
    db.run(
      `INSERT INTO messages (user, avatar, text, time) VALUES (?, ?, ?, ?)`,
      [messageData.user, messageData.avatar, messageData.text, messageData.time],
      function(err) {
        if (err) console.error('Error saving message:', err.message);
      }
    );

    db.run(`DELETE FROM messages WHERE id NOT IN (SELECT id FROM messages ORDER BY id DESC LIMIT 100)`);

    io.emit('chat message', messageData);
  });

  socket.on('typing', () => {
    const user = connectedUsers.get(socket.id);
    if (user && user.username) socket.broadcast.emit('typing', user.username);
  });

  socket.on('stop typing', () => {
    const user = connectedUsers.get(socket.id);
    if (user && user.username) socket.broadcast.emit('stop typing', user.username);
  });

  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user && user.username) {
      connectedUsers.delete(socket.id);
      broadcastUserList();
    }
    console.log(`🔴 Socket disconnected: ${socket.id}`);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Chat server running at http://0.0.0.0:${PORT}`);
});