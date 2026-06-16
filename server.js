const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Serve the HTML file when a user visits the root URL
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

// Real-Time WebSocket Logic
io.on('connection', (socket) => {
  console.log('🟢 A user connected!');

  // Broadcast the message to everyone when the server receives it
  socket.on('chat message', (msg) => {
    io.emit('chat message', msg); 
  });

  socket.on('disconnect', () => {
    console.log('🔴 A user disconnected');
  });
});

// Start the server on port 3000
const PORT = 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(` Chat server is running at http://192.168.100.92:${PORT}`);
});