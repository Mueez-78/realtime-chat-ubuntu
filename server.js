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
const connectedUsers = new Map(); // socket.id -> { username, messageTimestamps: [] }

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

  // Send existing history right away so it's ready before the user even sets a name
  socket.emit('load history', chatHistory);

  socket.on('set username', (rawUsername) => {
    // Halang kemasukan tanpa nama yang sah (buang fallback 'Anonymous')
    const username = String(rawUsername || '').trim().slice(0, MAX_USERNAME_LENGTH);
    if (!username) return; 

    connectedUsers.set(socket.id, { username, messageTimestamps: [] });

    broadcastUserList();
    // Mesej 'joined the chat' dipadamkan supaya tidak spam ketika refresh
  });

  socket.on('chat message', (data) => {
    const user = connectedUsers.get(socket.id);
    if (!user) return; // ignore messages from sockets that never set a username

    if (isRateLimited(user)) {
      socket.emit('rate limited');
      return;
    }

    const text = String((data && data.text) || '').trim().slice(0, MAX_MESSAGE_LENGTH);
    if (!text) return;

    const messageData = { user: user.username, text, time: timestamp() };
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
      // Mesej 'left the chat' dipadamkan supaya tidak spam ketika refresh
    }
    console.log(`🔴 Socket disconnected: ${socket.id}`);
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Chat server running at http://localhost:${PORT}`);
});