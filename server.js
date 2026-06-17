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

function isRateLimited(user) {
  const now = Date.now();
  user.messageTimestamps = user.messageTimestamps.filter((t) => now - t < RATE_LIMIT_WINDOW_MS);
  if (user.messageTimestamps.length >= RATE_LIMIT_MAX_MESSAGES) return true;
  user.messageTimestamps.push(now);
  return false;
}

io.on('connection', (socket) => {
  console.log(`🟢 Socket connected: ${socket.id}`);

  // Send existing history right away
  socket.emit('load history', chatHistory);

  socket.on('set username', (data) => {
    // Support both string format (old) or object format with avatar & flags (new)
    const rawUsername = typeof data === 'string' ? data : data.name;
    const username = String(rawUsername || '').trim().slice(0, MAX_USERNAME_LENGTH);
    if (!username) return; 

    // Accept avatar if provided (limit string size to ~150KB to protect server)
    let avatar = null;
    if (data && data.avatar && typeof data.avatar === 'string' && data.avatar.length < 150000) {
      avatar = data.avatar;
    }

    connectedUsers.set(socket.id, { username, avatar, messageTimestamps: [] });
    broadcastUserList();

    // Only broadcast "joined the chat" if it's a genuinely new user (not a reconnect)
    if (data && data.isNewUser) {
      addSystemMessage(`${username} joined the chat`);
    }
  });

  socket.on('chat message', (data) => {
    const user = connectedUsers.get(socket.id);
    if (!user) return; 

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
    if (user) socket.broadcast.emit('typing', user.username);
  });

  socket.on('stop typing', () => {
    const user = connectedUsers.get(socket.id);
    if (user) socket.broadcast.emit('stop typing', user.username);
  });

  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      connectedUsers.delete(socket.id);
      broadcastUserList();
      // Removed "left the chat" to prevent spam
    }
    console.log(`🔴 Socket disconnected: ${socket.id}`);
  });
});

// Listen on all IPs (0.0.0.0) so Cloudflare and local network can access it
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Chat server running at http://localhost:${PORT}`);
});