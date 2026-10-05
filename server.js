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
  else {
    console.log('📁 SQLite Database (chat.db) connected successfully.');
    db.run(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        avatar TEXT,
        text TEXT,
        time TEXT,
        serverId TEXT DEFAULT 'dit-lounge'
      )
    `, (err) => {
      if (!err) {
        db.run(`ALTER TABLE messages ADD COLUMN serverId TEXT DEFAULT 'dit-lounge'`, () => {});
      }
    });
  }
});

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

function isRateLimited(user) {
  const now = Date.now();
  user.messageTimestamps = user.messageTimestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (user.messageTimestamps.length >= RATE_LIMIT_MAX_MESSAGES) return true;
  user.messageTimestamps.push(now);
  return false;
}

io.on('connection', (socket) => {
  console.log(`🟢 Socket connected: ${socket.id}`);

  // ==========================================
  // FASA 3A: PENGESAHAN ADMIN
  // ==========================================
  socket.on('set username', (data) => {
    if (!data) return;

    const rawUsername = typeof data === 'string' ? data : data.name;
    if (typeof rawUsername !== 'string') return; 

    let username = rawUsername.trim().slice(0, MAX_USERNAME_LENGTH);
    if (!username || username === '[object Object]' || username === 'null') return; 

    let isAdmin = false;

    // Semak jika seseorang cuba menjadi Mueez (Admin)
    if (username.toLowerCase() === 'mueez') {
      if (data.password === '333333') {
        isAdmin = true;
        username = 'Mueez'; // Pastikan ejaan tepat
      } else {
        // Jika salah kata laluan, tolak permintaan
        socket.emit('login error', 'Kata laluan salah untuk akaun Admin (Mueez).');
        return;
      }
    }

    let avatar = null;
    if (data.avatar && typeof data.avatar === 'string' && data.avatar.length < 150000) {
      avatar = data.avatar;
    }

    connectedUsers.set(socket.id, { username, avatar, isAdmin, messageTimestamps: [], currentServer: 'dit-lounge' });
    broadcastUserList();
    
    // Beritahu frontend bahawa log masuk berjaya
    socket.emit('login success');
  });

  socket.on('join server', (serverId) => {
    const user = connectedUsers.get(socket.id);
    if (!user) return;

    socket.rooms.forEach(room => {
      if (room !== socket.id) socket.leave(room);
    });

    socket.join(serverId);
    user.currentServer = serverId;

    // Tambah 'id' dalam SELECT supaya frontend tahu ID mesej untuk dipadam
    db.all(
      `SELECT id, user, avatar, text, time FROM messages WHERE serverId = ? ORDER BY id DESC LIMIT ?`,
      [serverId, MAX_HISTORY],
      (err, rows) => {
        if (err) return console.error('Database read error:', err);
        const history = rows.reverse();
        socket.emit('load history', history);
      }
    );
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

    const serverId = data.serverId || user.currentServer || 'dit-lounge';

    const messageData = { 
      user: user.username, 
      avatar: user.avatar,
      text, 
      time: timestamp() 
    };
    
    // SIMPAN MESEJ & HANTAR BERSAMA ID BARU
    db.run(
      `INSERT INTO messages (user, avatar, text, time, serverId) VALUES (?, ?, ?, ?, ?)`,
      [messageData.user, messageData.avatar, messageData.text, messageData.time, serverId],
      function(err) {
        if (err) return console.error('Error saving message:', err.message);
        
        messageData.id = this.lastID; // Ambil ID dari SQLite
        io.to(serverId).emit('chat message', messageData);
      }
    );

    db.run(`DELETE FROM messages WHERE id NOT IN (SELECT id FROM messages ORDER BY id DESC LIMIT 100)`);
  });

  // ==========================================
  // FASA 3A: LOGIK PADAM MESEJ (DELETE FOR EVERYONE)
  // ==========================================
  socket.on('delete message', (msgId) => {
    const user = connectedUsers.get(socket.id);
    // Hanya proses jika pengguna ini adalah Admin
    if (user && user.isAdmin) {
      db.run(`DELETE FROM messages WHERE id = ?`, [msgId], (err) => {
        if (!err) {
          // Pancarkan arahan buang mesej ke SEMUA bilik
          io.emit('message deleted', msgId);
        }
      });
    }
  });

  socket.on('typing', () => {
    const user = connectedUsers.get(socket.id);
    if (user && user.username && user.currentServer) {
      socket.to(user.currentServer).emit('typing', user.username);
    }
  });

  socket.on('stop typing', () => {
    const user = connectedUsers.get(socket.id);
    if (user && user.username && user.currentServer) {
      socket.to(user.currentServer).emit('stop typing', user.username);
    }
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