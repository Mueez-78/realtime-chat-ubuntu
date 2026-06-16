const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Serve the HTML file
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Real-Time WebSocket Logic
io.on('connection', (socket) => {
  console.log('🟢 A user connected!');

  // Receive the message object { user, text } and broadcast it to everyone
  socket.on('chat message', (data) => {
    io.emit('chat message', data); 
  });

  socket.on('disconnect', () => {
    console.log('🔴 A user disconnected');
  });
});

// Start the server
const PORT = 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Chat server is running at http://192.168.100.92:${PORT}`);
});