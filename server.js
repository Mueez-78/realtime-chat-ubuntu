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
const MAX_STORED_PER_CHANNEL = 100;
const MAX_AVATAR_LENGTH = 150000;
const AVATAR_PATTERN = /^data:image\/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+=*$/;
const DEFAULT_CHANNEL = 'general';

// ==========================================
// SERVER + CHANNEL REGISTRY (backend is the authority on valid servers, channels and passcodes)
// Passcodes never leave the backend. Every server has the default 'general' channel.
// ==========================================
function channelMap(ids) {
  return new Map(ids.map((id) => [id, { id, name: id }]));
}

const SERVERS = new Map([
  ['dit-lounge',  { name: 'DIT Lounge',  passcode: null,      channels: channelMap(['general', 'programming', 'random']) }],
  ['gaming',      { name: 'Gaming',      passcode: '1234',    channels: channelMap(['general', 'valorant', 'gta']) }],
  ['study',       { name: 'Study',       passcode: 'dit2026', channels: channelMap(['general']) }],
  ['programming', { name: 'Programming', passcode: null,      channels: channelMap(['general']) }],
]);

// ==========================================
// DATABASE SETUP
// ==========================================
const db = new sqlite3.Database('./chat.db', (err) => {
  if (err) console.error('🔴 Failed to open database:', err.message);
  else console.log('📁 SQLite Database (chat.db) connected successfully.');
});

// Idempotent schema setup/migration for new and existing chat.db files. Existing rows are never removed.
function migrateDatabase(done) {
  db.run(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      avatar TEXT,
      text TEXT,
      time TEXT,
      serverId TEXT DEFAULT 'dit-lounge',
      channelId TEXT DEFAULT 'general'
    )
  `, (err) => {
    if (err) return done(err);
    db.all(`PRAGMA table_info(messages)`, (err, columns) => {
      if (err) return done(err);
      const names = new Set(columns.map((c) => c.name));
      db.serialize(() => {
        if (!names.has('serverId')) db.run(`ALTER TABLE messages ADD COLUMN serverId TEXT DEFAULT 'dit-lounge'`);
        if (!names.has('channelId')) db.run(`ALTER TABLE messages ADD COLUMN channelId TEXT DEFAULT 'general'`);
        // Pre-channel messages belong to their server's 'general' channel
        db.run(`UPDATE messages SET serverId = 'dit-lounge' WHERE serverId IS NULL`);
        db.run(`UPDATE messages SET channelId = ? WHERE channelId IS NULL`, [DEFAULT_CHANNEL]);
        db.run(`CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages (serverId, channelId, id)`, done);
      });
    });
  });
}

const connectedUsers = new Map(); 

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function timestamp() {
  return new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
}

function isValidServerId(serverId) {
  return typeof serverId === 'string' && SERVERS.has(serverId);
}

function isValidChannelId(serverId, channelId) {
  return isValidServerId(serverId) && typeof channelId === 'string' && SERVERS.get(serverId).channels.has(channelId);
}

// Only call with ids that passed isValidChannelId
function getChannelRoom(serverId, channelId) {
  return `${serverId}:${channelId}`;
}

function sendChannelHistory(socket, serverId, channelId) {
  // Tambah 'id' dalam SELECT supaya frontend tahu ID mesej untuk dipadam
  db.all(
    `SELECT id, user, avatar, text, time FROM messages WHERE serverId = ? AND channelId = ? ORDER BY id DESC LIMIT ?`,
    [serverId, channelId, MAX_HISTORY],
    (err, rows) => {
      if (err) return console.error('Database read error:', err);
      socket.emit('load history', rows.reverse());
    }
  );
}

function sanitizeUsername(raw) {
  if (typeof raw !== 'string') return null;
  const username = raw.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, MAX_USERNAME_LENGTH);
  if (!username || username === '[object Object]' || username === 'null') return null;
  return username;
}

// Send the online list of one server only to the sockets in that server
function broadcastUserList(serverId) {
  if (!serverId) return;
  const usernames = [];
  for (const u of connectedUsers.values()) {
    if (u.currentServer === serverId) usernames.push(u.username);
  }
  io.to(serverId).emit('user list', usernames);
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
    if (!data || (typeof data !== 'string' && typeof data !== 'object')) return;

    let username = sanitizeUsername(typeof data === 'string' ? data : data.name);
    if (!username) return;

    const password = typeof data.password === 'string' ? data.password : '';
    let isAdmin = false;

    // Semak jika seseorang cuba menjadi Mueez (Admin)
    if (username.toLowerCase() === 'mueez') {
      if (password === '333333') {
        isAdmin = true;
        username = 'Mueez'; // Pastikan ejaan tepat
      } else {
        // Jika salah kata laluan, tolak permintaan
        socket.emit('login error', 'Kata laluan salah untuk akaun Admin (Mueez).');
        return;
      }
    }

    let avatar = null;
    if (typeof data.avatar === 'string' && data.avatar.length < MAX_AVATAR_LENGTH && AVATAR_PATTERN.test(data.avatar)) {
      avatar = data.avatar;
    }

    const existing = connectedUsers.get(socket.id);
    if (existing) {
      // Profile change on the same connection: keep the joined server and rate-limit state
      if (existing.currentServer && existing.username !== username) {
        socket.to(getChannelRoom(existing.currentServer, existing.currentChannel)).emit('stop typing', existing.username);
      }
      Object.assign(existing, { username, avatar, isAdmin });
      broadcastUserList(existing.currentServer);
    } else {
      // currentServer/currentChannel stay null until a validated 'join server'
      connectedUsers.set(socket.id, { username, avatar, isAdmin, messageTimestamps: [], currentServer: null, currentChannel: null });
    }

    // Beritahu frontend bahawa log masuk berjaya
    socket.emit('login success');
  });

  // Leave the current channel room, clearing any typing indicator this user left behind there
  function leaveCurrentChannel(user) {
    if (!user.currentServer) return;
    const room = getChannelRoom(user.currentServer, user.currentChannel);
    socket.leave(room);
    socket.to(room).emit('stop typing', user.username);
  }

  // Payload: { serverId, passcode, channelId? } (or a bare serverId string). channelId defaults to 'general'.
  // Optional ack gets { ok, serverId, channelId } or { ok: false, error }.
  socket.on('join server', (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    const user = connectedUsers.get(socket.id);
    if (!user) return reply({ ok: false, error: 'Sila masukkan nama untuk mula.' });

    const serverId = typeof payload === 'string' ? payload : payload && payload.serverId;
    if (!isValidServerId(serverId)) return reply({ ok: false, error: 'Pelayan tidak wujud.' });

    const requestedChannel = payload && typeof payload === 'object' ? payload.channelId : undefined;
    const channelId = requestedChannel === undefined ? DEFAULT_CHANNEL : requestedChannel;
    if (!isValidChannelId(serverId, channelId)) return reply({ ok: false, error: 'Saluran tidak wujud.' });

    const server = SERVERS.get(serverId);
    if (server.passcode !== null) {
      const passcode = payload && typeof payload.passcode === 'string' ? payload.passcode : null;
      if (passcode !== server.passcode) return reply({ ok: false, error: 'Kod laluan salah. Akses ditolak!' });
    }

    const previousServer = user.currentServer;
    leaveCurrentChannel(user);
    if (previousServer) socket.leave(previousServer);

    socket.join(serverId);
    socket.join(getChannelRoom(serverId, channelId));
    user.currentServer = serverId;
    user.currentChannel = channelId;

    if (previousServer && previousServer !== serverId) broadcastUserList(previousServer);
    broadcastUserList(serverId);
    reply({ ok: true, serverId, channelId });

    sendChannelHistory(socket, serverId, channelId);
  });

  // Switch channel inside the server this socket already joined (servers are only entered via 'join server').
  // Payload: { serverId, channelId }. Optional ack gets { ok, serverId, channelId } or { ok: false, error }.
  socket.on('join channel', (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    const user = connectedUsers.get(socket.id);
    if (!user || !user.currentServer) return reply({ ok: false, error: 'Sila sertai pelayan dahulu.' });
    if (!payload || typeof payload !== 'object') return reply({ ok: false, error: 'Saluran tidak wujud.' });

    const { serverId, channelId } = payload;
    if (serverId !== user.currentServer) return reply({ ok: false, error: 'Sila sertai pelayan itu dahulu.' });
    if (!isValidChannelId(serverId, channelId)) return reply({ ok: false, error: 'Saluran tidak wujud.' });

    leaveCurrentChannel(user);
    socket.join(getChannelRoom(serverId, channelId));
    user.currentChannel = channelId;
    reply({ ok: true, serverId, channelId });

    sendChannelHistory(socket, serverId, channelId);
  });

  socket.on('chat message', (data) => {
    const user = connectedUsers.get(socket.id);
    if (!user || !user.username || !user.currentServer) return;
    if (!data || typeof data !== 'object' || typeof data.text !== 'string') return;

    // The client's serverId/channelId are only hints; a mismatch means a stale or forged target
    if (data.serverId !== undefined && data.serverId !== user.currentServer) return;
    if (data.channelId !== undefined && data.channelId !== user.currentChannel) return;

    if (isRateLimited(user)) {
      socket.emit('rate limited');
      return;
    }

    const text = data.text.trim().slice(0, MAX_MESSAGE_LENGTH);
    if (!text) return;

    const serverId = user.currentServer;
    const channelId = user.currentChannel;

    const messageData = {
      user: user.username, 
      avatar: user.avatar,
      text, 
      time: timestamp() 
    };
    
    // SIMPAN MESEJ & HANTAR BERSAMA ID BARU
    db.run(
      `INSERT INTO messages (user, avatar, text, time, serverId, channelId) VALUES (?, ?, ?, ?, ?, ?)`,
      [messageData.user, messageData.avatar, messageData.text, messageData.time, serverId, channelId],
      function(err) {
        if (err) return console.error('Error saving message:', err.message);

        messageData.id = this.lastID; // Ambil ID dari SQLite
        io.to(getChannelRoom(serverId, channelId)).emit('chat message', messageData);

        // Retention is per channel: only this channel's oldest messages are pruned
        db.run(
          `DELETE FROM messages WHERE serverId = ? AND channelId = ? AND id NOT IN (SELECT id FROM messages WHERE serverId = ? AND channelId = ? ORDER BY id DESC LIMIT ?)`,
          [serverId, channelId, serverId, channelId, MAX_STORED_PER_CHANNEL]
        );
      }
    );
  });

  // ==========================================
  // FASA 3A: LOGIK PADAM MESEJ (DELETE FOR EVERYONE)
  // ==========================================
  socket.on('delete message', (msgId) => {
    const user = connectedUsers.get(socket.id);
    // Hanya proses jika pengguna ini adalah Admin
    if (!user || !user.isAdmin) return;
    if (!Number.isSafeInteger(msgId) || msgId <= 0) return;

    db.get(`SELECT serverId, channelId FROM messages WHERE id = ?`, [msgId], (err, row) => {
      if (err || !row) return;
      // Admin can only delete messages in the server + channel they are currently in
      if (row.serverId !== user.currentServer || row.channelId !== user.currentChannel) return;

      db.run(`DELETE FROM messages WHERE id = ?`, [msgId], function (err) {
        if (err || this.changes === 0) return;
        // Hanya pelanggan dalam saluran mesej itu menerima arahan buang
        io.to(getChannelRoom(row.serverId, row.channelId)).emit('message deleted', msgId);
      });
    });
  });

  socket.on('typing', () => {
    const user = connectedUsers.get(socket.id);
    if (user && user.username && user.currentServer) {
      socket.to(getChannelRoom(user.currentServer, user.currentChannel)).emit('typing', user.username);
    }
  });

  socket.on('stop typing', () => {
    const user = connectedUsers.get(socket.id);
    if (user && user.username && user.currentServer) {
      socket.to(getChannelRoom(user.currentServer, user.currentChannel)).emit('stop typing', user.username);
    }
  });

  socket.on('disconnect', () => {
    const user = connectedUsers.get(socket.id);
    if (user) {
      connectedUsers.delete(socket.id);
      if (user.currentServer) {
        // Don't leave a stale "is typing…" behind for the others
        io.to(getChannelRoom(user.currentServer, user.currentChannel)).emit('stop typing', user.username);
        broadcastUserList(user.currentServer);
      }
    }
    console.log(`🔴 Socket disconnected: ${socket.id}`);
  });
});

// Start accepting connections only once the schema is ready
migrateDatabase((err) => {
  if (err) console.error('🔴 Database migration failed:', err.message);
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Chat server running at http://0.0.0.0:${PORT}`);
  });
});