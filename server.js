const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Store the last 50 messages in memory
const chatHistory = [];

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

io.on('connection', (socket) => {
  console.log('🟢 A user connected!');

  // Send the existing chat history to the newly connected user
  socket.emit('load history', chatHistory);

  // When a new message is received
  socket.on('chat message', (data) => {
    // Add timestamp
    const currentTime = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    const messageData = { ...data, time: currentTime };

    // Save to history (keep only the last 50 messages to save memory)
    chatHistory.push(messageData);
    if (chatHistory.length > 50) {
      chatHistory.shift(); 
    }

    // Broadcast to everyone
    io.emit('chat message', messageData); 
  });

  socket.on('disconnect', () => {
    console.log('🔴 A user disconnected');
  });
});

const PORT = 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Chat server is running at http://192.168.100.92:${PORT}`);
});