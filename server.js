const express = require('express');
const http = require('http');
const path = require('path');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const MAX_HISTORY = 50;
const MAX_MESSAGE_LENGTH = 500;
const MAX_USERNAME_LENGTH = 24;
const RATE_LIMIT_WINDOW_MS = 3000;
const RATE_LIMIT_MAX_MESSAGES = 5;

// Memori Pelayan
const chatHistory = [];
const connectedUsers = new Map(); // socket.id -> { username, avatar, messageTimestamps: [] }

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

function pushHistory(messageData) {
  chatHistory.push(messageData);
  if (chatHistory.length > MAX_HISTORY) chatHistory.shift();
}

function addSystemMessage(text) {
  const messageData = { system: true, text, time: timestamp() };
  pushHistory(messageData);
  io.emit('chat message', messageData);
}

// Sistem Anti-Spam
function isRateLimited(user) {
  const now = Date.now();
  user.messageTimestamps = user.messageTimestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (user.messageTimestamps.length >= RATE_LIMIT_MAX_MESSAGES) return true;
  user.messageTimestamps.push(now);
  return false;
}

io.on('connection', (socket) => {
  console.log(`🟢 Socket connected: ${socket.id}`);

  // Hantar sejarah chat kepada pengguna yang baru masuk
  socket.emit('load history', chatHistory);

  // LOGIK MENDAFTAR PENGGUNA (STRICT VALIDATION)
  socket.on('set username', (data) => {
    if (!data) return;

    // Pastikan format nama adalah teks (string) yang sah, elakkan [object Object]
    const rawUsername = typeof data === 'string' ? data : data.name;
    if (typeof rawUsername !== 'string') return; 

    // Bersihkan nama
    const username = rawUsername.trim().slice(0, MAX_USERNAME_LENGTH);
    
    // TEMBOK KESELAMATAN: Jika nama kosong atau meragukan, HALANG!
    if (!username || username === '[object Object]' || username === 'null') return; 

    // Proses gambar profil jika ada
    let avatar = null;
    if (data.avatar && typeof data.avatar === 'string' && data.avatar.length < 150000) {
      avatar = data.avatar;
    }

    // Daftarkan pengguna ke dalam sistem
    connectedUsers.set(socket.id, { username, avatar, messageTimestamps: [] });
    broadcastUserList();

    // Hanya isytihar "Joined" jika ia pendaftaran baharu (bukan sekadar reconnect)
    if (data.isNewUser) {
      addSystemMessage(`${username} joined the chat`);
    }
  });

  // LOGIK MENGHANTAR MESEJ
  socket.on('chat message', (data) => {
    const user = connectedUsers.get(socket.id);
    
    // TEMBOK KESELAMATAN: Jika pengguna belum daftar nama (bypass), HALANG mesej!
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
    
    pushHistory(messageData);
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

// Dengar pada semua port rangkaian
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Chat server running at http://0.0.0.0:${PORT}`);
});