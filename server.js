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

// In-memory state
const chatHistory = [];
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

function pushHistory(messageData) {
  chatHistory.push(messageData);
  if (chatHistory.length > MAX_HISTORY) chatHistory.shift();
}

// System message function removed completely as requested

function isRateLimited(user) {
  const now = Date.now();
  user.messageTimestamps = user.messageTimestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (user.messageTimestamps.length >= RATE_LIMIT_MAX_MESSAGES) return true;
  user.messageTimestamps.push(now);
  return false;
}

io.on('connection', (socket) => {
  console.log(`🟢 Socket connected: ${socket.id}`);

  socket.emit('load history', chatHistory);

  socket.on('set username', (data) => {
    if (!data) return;

    // FIX: Properly handle both old string format and new object format
    const rawUsername = typeof data === 'string' ? data : data.name;
    if (typeof rawUsername !== 'string') return; 

    const username = rawUsername.trim().slice(0, MAX_USERNAME_LENGTH);
    
    // Safety check against the [object Object] bug
    if (!username || username === '[object Object]' || username === 'null') return; 

    let avatar = null;
    if (data.avatar && typeof data.avatar === 'string' && data.avatar.length < 150000) {
      avatar = data.avatar;
    }

    connectedUsers.set(socket.id, { username, avatar, messageTimestamps: [] });
    broadcastUserList();

    // "Joined the chat" broadcast has been entirely removed here.
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

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Chat server running at http://0.0.0.0:${PORT}`);
});