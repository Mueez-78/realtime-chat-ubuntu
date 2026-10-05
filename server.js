const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
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
const MAX_SERVERS = 50;
const MAX_SERVER_NAME_LENGTH = 32;
const MAX_SERVER_ID_LENGTH = 24;
const MAX_ICON_CODE_POINTS = 8;
const MAX_PASSCODE_LENGTH = 64;
const SERVER_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const DEFAULT_SERVER_ICON = '💬';

// ==========================================
// SERVER + CHANNEL REGISTRY (backend is the authority on valid servers, channels and passcodes)
// Stored in the 'servers' and 'channels' tables and loaded into SERVERS at startup.
// Passcodes are only kept as scrypt hashes and never leave the backend. Every server has a 'general' channel.
// ==========================================
const SERVERS = new Map(); // serverId -> { name, icon, passcodeHash, position, channels: Map(channelId -> { id, name }) }

// Built-in servers, inserted only when missing (INSERT OR IGNORE), so later admin changes are never overwritten.
// The original passcodes ('gaming' and 'study') are stored pre-hashed so no plaintext passcode lives in the code.
const SEED_SERVERS = [
  { id: 'dit-lounge',  name: 'DIT Lounge',  icon: '🟢', passcodeHash: null, channels: ['general', 'programming', 'random'] },
  { id: 'gaming',      name: 'Gaming',      icon: '🎮', passcodeHash: 'scrypt$a74918d2354411238aac9034c5c57ba5$d2c4d510479b2702e0bcf176d8dff4d4e052be9f10db68ce38e611c704a1b0de', channels: ['general', 'valorant', 'gta'] },
  { id: 'study',       name: 'Study',       icon: '📚', passcodeHash: 'scrypt$f0dfc002137458fb1d80a398625bbb06$d0d695b65f63ffa2771c75b799a8d2b8346b4e0974b593e45db3098d341a06d9', channels: ['general'] },
  { id: 'programming', name: 'Programming', icon: '💻', passcodeHash: null, channels: ['general'] },
];

// ==========================================
// PASSCODE HASHING (scrypt from Node's built-in crypto; async so the event loop stays free)
// Format: scrypt$<salt hex>$<derived key hex>
// ==========================================
const SCRYPT_KEY_LENGTH = 32;

function hashPasscode(passcode) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(passcode, salt, SCRYPT_KEY_LENGTH, (err, key) => {
      if (err) return reject(err);
      resolve(`scrypt$${salt.toString('hex')}$${key.toString('hex')}`);
    });
  });
}

function verifyPasscode(passcode, stored) {
  return new Promise((resolve) => {
    const [scheme, saltHex, keyHex] = String(stored).split('$');
    if (scheme !== 'scrypt' || !saltHex || !keyHex) return resolve(false);
    const expected = Buffer.from(keyHex, 'hex');
    crypto.scrypt(passcode, Buffer.from(saltHex, 'hex'), expected.length, (err, key) => {
      resolve(!err && crypto.timingSafeEqual(key, expected));
    });
  });
}

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
        db.run(`CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages (serverId, channelId, id)`);

        // Server/channel registry (Phase 5). passcodeHash NULL = open server.
        db.run(`
          CREATE TABLE IF NOT EXISTS servers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            icon TEXT NOT NULL,
            passcodeHash TEXT,
            position INTEGER NOT NULL DEFAULT 0
          )
        `);
        db.run(`
          CREATE TABLE IF NOT EXISTS channels (
            serverId TEXT NOT NULL,
            id TEXT NOT NULL,
            name TEXT NOT NULL,
            position INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (serverId, id)
          )
        `);
        SEED_SERVERS.forEach((s, serverIndex) => {
          db.run(`INSERT OR IGNORE INTO servers (id, name, icon, passcodeHash, position) VALUES (?, ?, ?, ?, ?)`,
            [s.id, s.name, s.icon, s.passcodeHash, serverIndex]);
          s.channels.forEach((channelId, channelIndex) => {
            db.run(`INSERT OR IGNORE INTO channels (serverId, id, name, position) VALUES (?, ?, ?, ?)`,
              [s.id, channelId, channelId, channelIndex]);
          });
        });
        db.run(`SELECT 1`, done); // runs after everything queued above
      });
    });
  });
}

// Rebuild the in-memory registry from the database
function loadRegistry(done) {
  db.all(`SELECT id, name, icon, passcodeHash, position FROM servers ORDER BY position, rowid`, (err, servers) => {
    if (err) return done(err);
    db.all(`SELECT serverId, id, name FROM channels ORDER BY position, rowid`, (err, channels) => {
      if (err) return done(err);
      SERVERS.clear();
      servers.forEach((s) => {
        SERVERS.set(s.id, { name: s.name, icon: s.icon, passcodeHash: s.passcodeHash, position: s.position, channels: new Map() });
      });
      channels.forEach((c) => {
        const server = SERVERS.get(c.serverId);
        if (server) server.channels.set(c.id, { id: c.id, name: c.name });
      });
      done(null);
    });
  });
}

// Public navigation metadata. Fields are whitelisted: passcode hashes never leave the backend.
function publicServerList() {
  return Array.from(SERVERS, ([id, s]) => ({
    id,
    name: s.name,
    icon: s.icon,
    isLocked: s.passcodeHash !== null,
    channels: Array.from(s.channels.values(), (c) => ({ id: c.id, name: c.name })),
  }));
}

const connectedUsers = new Map(); 

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Public navigation metadata for the frontend
app.get('/api/servers', (req, res) => {
  res.json(publicServerList());
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
  // 'id' is included so the frontend can address messages for deletion
  db.all(
    `SELECT id, user, avatar, text, time FROM messages WHERE serverId = ? AND channelId = ? ORDER BY id DESC LIMIT ?`,
    [serverId, channelId, MAX_HISTORY],
    (err, rows) => {
      if (err) return console.error('Database read error:', err);
      // The admin name is reserved, so it alone identifies admin messages (lets the UI badge them without knowing the name)
      socket.emit('load history', rows.reverse().map((row) => ({ ...row, isAdmin: row.user === ADMIN_USERNAME })));
    }
  );
}

function sanitizeUsername(raw) {
  if (typeof raw !== 'string') return null;
  const username = raw.replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, MAX_USERNAME_LENGTH);
  if (!username || username === '[object Object]' || username === 'null') return null;
  return username;
}

function sanitizeAvatar(raw) {
  return typeof raw === 'string' && raw.length < MAX_AVATAR_LENGTH && AVATAR_PATTERN.test(raw) ? raw : null;
}

// ==========================================
// ADMIN (credentials never leave the backend; admin status lives only on the socket)
// ==========================================
const ADMIN_USERNAME = 'Mueez';
const ADMIN_PASSWORD = '333333';
const LOCKOUT_WINDOW_MS = 10 * 60 * 1000;
const TOO_MANY_ATTEMPTS = 'Too many attempts. Please try again later.';

// Counts failed attempts per key (client IP) within a sliding window
function createFailureLimiter(maxFailures) {
  const failures = new Map(); // key -> timestamps of recent failures
  const recent = (key) => (failures.get(key) || []).filter((t) => Date.now() - t < LOCKOUT_WINDOW_MS);
  return {
    isBlocked(key) {
      const list = recent(key);
      if (list.length) failures.set(key, list); else failures.delete(key);
      return list.length >= maxFailures;
    },
    fail(key) { failures.set(key, [...recent(key), Date.now()]); },
    reset(key) { failures.delete(key); },
  };
}

const adminLimiter = createFailureLimiter(5);
const passcodeLimiter = createFailureLimiter(10);

function isAdminName(name) {
  return name.toLowerCase() === ADMIN_USERNAME.toLowerCase();
}

// Returns null when the credentials are valid, otherwise an error message. Failed attempts are throttled per IP.
function checkAdminCredentials(socket, username, password) {
  const ip = socket.handshake.address;
  if (adminLimiter.isBlocked(ip)) return TOO_MANY_ATTEMPTS;
  if (isAdminName(username) && password === ADMIN_PASSWORD) {
    adminLimiter.reset(ip);
    return null;
  }
  adminLimiter.fail(ip);
  return 'Incorrect admin username or password.';
}

// ---------- Validation for admin-created servers ----------
function sanitizeServerName(raw) {
  if (typeof raw !== 'string') return null;
  const name = raw.replace(/[\u0000-\u001F\u007F]/g, '').replace(/\s+/g, ' ').trim();
  return name && name.length <= MAX_SERVER_NAME_LENGTH ? name : null;
}

// Short emoji/text icon; empty means the default icon
function sanitizeIcon(raw) {
  if (raw === undefined || raw === null || raw === '') return DEFAULT_SERVER_ICON;
  if (typeof raw !== 'string') return null;
  const icon = raw.replace(/[\u0000-\u001F\u007F\s]/g, '');
  if (!icon) return DEFAULT_SERVER_ICON;
  return Array.from(icon).length <= MAX_ICON_CODE_POINTS ? icon : null;
}

// undefined / null / '' => no passcode (open server). Returns { ok, passcode } or { ok: false, error }.
function parseNewPasscode(raw) {
  if (raw === undefined || raw === null || raw === '') return { ok: true, passcode: null };
  if (typeof raw !== 'string') return { ok: false, error: 'Invalid password.' };
  if (raw.length > MAX_PASSCODE_LENGTH) return { ok: false, error: `Password must be at most ${MAX_PASSCODE_LENGTH} characters.` };
  if (/[\u0000-\u001F\u007F]/.test(raw)) return { ok: false, error: 'Password contains invalid characters.' };
  if (raw.trim() !== raw) return { ok: false, error: 'Password cannot start or end with a space.' };
  return { ok: true, passcode: raw };
}

// Ids are derived from the name: lowercase letters, digits and single dashes only, so they are safe as
// Map keys and Socket.IO room names (no ':' that could collide with 'server:channel' rooms).
const pendingServerIds = new Set(); // ids reserved by creations still being written
function generateServerId(name) {
  const base = name.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, MAX_SERVER_ID_LENGTH).replace(/-+$/, '') || 'server';
  const taken = (id) => SERVERS.has(id) || pendingServerIds.has(id);
  if (!taken(base)) return base;
  for (let n = 2; ; n++) {
    const suffix = `-${n}`;
    const id = base.slice(0, MAX_SERVER_ID_LENGTH - suffix.length).replace(/-+$/, '') + suffix;
    if (!taken(id)) return id;
  }
}

// Let every client refetch GET /api/servers (e.g. after a new server or a lock change)
function announceServersChanged() {
  io.emit('servers updated');
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
  // IDENTITY: GUESTS + ADMIN AUTHENTICATION
  // ==========================================
  // Guest identity. The admin name is reserved: it only passes with valid admin credentials.
  socket.on('set username', (data) => {
    if (!data || (typeof data !== 'string' && typeof data !== 'object')) return;

    let username = sanitizeUsername(typeof data === 'string' ? data : data.name);
    if (!username) return;

    const password = typeof data.password === 'string' ? data.password : '';
    let isAdmin = false;

    // Someone is trying to use the admin name
    if (isAdminName(username)) {
      // Older clients sent the admin password along with the name; the new UI uses 'admin login'
      const error = password ? checkAdminCredentials(socket, username, password) : 'This name is reserved. Please choose another.';
      if (error) {
        socket.emit('login error', error);
        return;
      }
      isAdmin = true;
      username = ADMIN_USERNAME; // canonical spelling
    }

    registerUser(username, sanitizeAvatar(data.avatar), isAdmin);
  });

  // Admin sign-in from the entry screen. Payload: { username, password, avatar? }; ack gets { ok, username } or { ok: false, error }.
  // Admin status lives only on this socket; nothing is stored client-side.
  socket.on('admin login', (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    if (!payload || typeof payload !== 'object') return reply({ ok: false, error: 'Invalid request.' });

    const username = sanitizeUsername(payload.username) || '';
    const password = typeof payload.password === 'string' ? payload.password : '';
    const error = checkAdminCredentials(socket, username, password);
    if (error) return reply({ ok: false, error });

    reply({ ok: true, username: ADMIN_USERNAME });
    registerUser(ADMIN_USERNAME, sanitizeAvatar(payload.avatar), true);
  });

  function registerUser(username, avatar, isAdmin) {
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

    // Tell the frontend the sign-in succeeded, with the confirmed identity
    socket.emit('login success', { username, isAdmin });
  }

  // Leave the current channel room, clearing any typing indicator this user left behind there
  function leaveCurrentChannel(user) {
    if (!user.currentServer) return;
    const room = getChannelRoom(user.currentServer, user.currentChannel);
    socket.leave(room);
    socket.to(room).emit('stop typing', user.username);
  }

  // Every join request bumps this; a passcode check that finishes after a newer join was requested is dropped
  let joinSeq = 0;

  // Payload: { serverId, passcode, channelId? } (or a bare serverId string). channelId defaults to 'general'.
  // Optional ack gets { ok, serverId, channelId } or { ok: false, error }.
  socket.on('join server', (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    const user = connectedUsers.get(socket.id);
    if (!user) return reply({ ok: false, error: 'Please enter a name to start.' });

    const serverId = typeof payload === 'string' ? payload : payload && payload.serverId;
    if (!isValidServerId(serverId)) return reply({ ok: false, error: 'That server does not exist.' });

    const requestedChannel = payload && typeof payload === 'object' ? payload.channelId : undefined;
    const channelId = requestedChannel === undefined ? DEFAULT_CHANNEL : requestedChannel;
    if (!isValidChannelId(serverId, channelId)) return reply({ ok: false, error: 'That channel does not exist.' });

    const seq = ++joinSeq;
    const passcodeHash = SERVERS.get(serverId).passcodeHash;
    if (passcodeHash === null) return enterServer(user, serverId, channelId, reply);

    const ip = socket.handshake.address;
    const passcode = payload && typeof payload.passcode === 'string' ? payload.passcode : null;
    if (passcode === null || passcode.length > MAX_PASSCODE_LENGTH) return reply({ ok: false, error: 'Wrong server password. Access denied.' });
    if (passcodeLimiter.isBlocked(ip)) return reply({ ok: false, error: TOO_MANY_ATTEMPTS });

    verifyPasscode(passcode, passcodeHash).then((valid) => {
      // The socket may have left, been replaced, or asked for another server meanwhile
      if (connectedUsers.get(socket.id) !== user || seq !== joinSeq) return reply({ ok: false, error: 'Request superseded.' });
      if (!valid) {
        passcodeLimiter.fail(ip);
        return reply({ ok: false, error: 'Wrong server password. Access denied.' });
      }
      enterServer(user, serverId, channelId, reply);
    });
  });

  function enterServer(user, serverId, channelId, reply) {
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
  }

  // Switch channel inside the server this socket already joined (servers are only entered via 'join server').
  // Payload: { serverId, channelId }. Optional ack gets { ok, serverId, channelId } or { ok: false, error }.
  socket.on('join channel', (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    const user = connectedUsers.get(socket.id);
    if (!user || !user.currentServer) return reply({ ok: false, error: 'Join a server first.' });
    if (!payload || typeof payload !== 'object') return reply({ ok: false, error: 'That channel does not exist.' });

    const { serverId, channelId } = payload;
    if (serverId !== user.currentServer) return reply({ ok: false, error: 'Join that server first.' });
    if (!isValidChannelId(serverId, channelId)) return reply({ ok: false, error: 'That channel does not exist.' });

    joinSeq++; // supersedes any server join still checking a passcode
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
      isAdmin: user.isAdmin,
      text, 
      time: timestamp() 
    };
    
    // Save the message, then broadcast it with its new id
    db.run(
      `INSERT INTO messages (user, avatar, text, time, serverId, channelId) VALUES (?, ?, ?, ?, ?, ?)`,
      [messageData.user, messageData.avatar, messageData.text, messageData.time, serverId, channelId],
      function(err) {
        if (err) return console.error('Error saving message:', err.message);

        messageData.id = this.lastID; // id assigned by SQLite
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
  // ADMIN: DELETE MESSAGE (for everyone)
  // ==========================================
  socket.on('delete message', (msgId) => {
    const user = connectedUsers.get(socket.id);
    // Admins only (server-side flag set by a verified admin login)
    if (!user || !user.isAdmin) return;
    if (!Number.isSafeInteger(msgId) || msgId <= 0) return;

    db.get(`SELECT serverId, channelId FROM messages WHERE id = ?`, [msgId], (err, row) => {
      if (err || !row) return;
      // Admin can only delete messages in the server + channel they are currently in
      if (row.serverId !== user.currentServer || row.channelId !== user.currentChannel) return;

      db.run(`DELETE FROM messages WHERE id = ?`, [msgId], function (err) {
        if (err || this.changes === 0) return;
        // Only clients in that message's channel are told to remove it
        io.to(getChannelRoom(row.serverId, row.channelId)).emit('message deleted', msgId);
      });
    });
  });

  // ==========================================
  // ADMIN: SERVER MANAGEMENT
  // ==========================================
  function requireAdmin(reply) {
    const user = connectedUsers.get(socket.id);
    if (user && user.isAdmin) return user;
    reply({ ok: false, error: 'Admin access required.' });
    return null;
  }

  // Payload: { name, icon?, passcode? }. The id is generated from the name; a 'general' channel is created.
  // Ack gets { ok: true, server: <public metadata> } or { ok: false, error }.
  socket.on('create server', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    if (!requireAdmin(reply)) return;
    if (!payload || typeof payload !== 'object') return reply({ ok: false, error: 'Invalid request.' });

    const name = sanitizeServerName(payload.name);
    if (!name) return reply({ ok: false, error: `Server name must be 1–${MAX_SERVER_NAME_LENGTH} characters.` });
    const lower = name.toLowerCase();
    if (Array.from(SERVERS.values()).some((s) => s.name.toLowerCase() === lower)) {
      return reply({ ok: false, error: 'A server with that name already exists.' });
    }
    const icon = sanitizeIcon(payload.icon);
    if (!icon) return reply({ ok: false, error: 'Icon must be a short emoji or text.' });
    const parsed = parseNewPasscode(payload.passcode);
    if (!parsed.ok) return reply({ ok: false, error: parsed.error });
    if (SERVERS.size + pendingServerIds.size >= MAX_SERVERS) return reply({ ok: false, error: `Server limit (${MAX_SERVERS}) reached.` });

    const id = generateServerId(name);
    if (!SERVER_ID_PATTERN.test(id)) return reply({ ok: false, error: 'Could not create a valid server id.' });
    pendingServerIds.add(id);
    try {
      const passcodeHash = parsed.passcode === null ? null : await hashPasscode(parsed.passcode);
      const position = Math.max(-1, ...Array.from(SERVERS.values(), (s) => s.position)) + 1;
      // Two plain inserts rather than BEGIN/COMMIT: the connection is shared, so a transaction here could
      // swallow other sockets' writes. If the channel insert fails, the server row is removed again.
      const run = (sql, params) => new Promise((resolve, reject) => db.run(sql, params, (err) => (err ? reject(err) : resolve())));
      await run(`INSERT INTO servers (id, name, icon, passcodeHash, position) VALUES (?, ?, ?, ?, ?)`, [id, name, icon, passcodeHash, position]);
      try {
        await run(`INSERT INTO channels (serverId, id, name, position) VALUES (?, ?, ?, 0)`, [id, DEFAULT_CHANNEL, DEFAULT_CHANNEL]);
      } catch (err) {
        await run(`DELETE FROM servers WHERE id = ?`, [id]).catch(() => {});
        throw err;
      }
      SERVERS.set(id, { name, icon, passcodeHash, position, channels: new Map([[DEFAULT_CHANNEL, { id: DEFAULT_CHANNEL, name: DEFAULT_CHANNEL }]]) });
      console.log(`🆕 Server created: ${id}`);
      reply({ ok: true, server: publicServerList().find((s) => s.id === id) });
      announceServersChanged();
    } catch (err) {
      console.error('Could not create server:', err.message);
      reply({ ok: false, error: 'Could not create the server. Please try again.' });
    } finally {
      pendingServerIds.delete(id);
    }
  });

  // Payload: { serverId, passcode }. An empty/null passcode removes the lock.
  // Members already inside stay connected; only new joins need the new password.
  socket.on('set server passcode', async (payload, ack) => {
    const reply = typeof ack === 'function' ? ack : () => {};
    if (!requireAdmin(reply)) return;
    if (!payload || typeof payload !== 'object') return reply({ ok: false, error: 'Invalid request.' });
    const { serverId } = payload;
    if (!isValidServerId(serverId)) return reply({ ok: false, error: 'That server does not exist.' });
    const parsed = parseNewPasscode(payload.passcode);
    if (!parsed.ok) return reply({ ok: false, error: parsed.error });

    try {
      const passcodeHash = parsed.passcode === null ? null : await hashPasscode(parsed.passcode);
      await new Promise((resolve, reject) => {
        db.run(`UPDATE servers SET passcodeHash = ? WHERE id = ?`, [passcodeHash, serverId], function (err) {
          if (err) return reject(err);
          if (this.changes !== 1) return reject(new Error('server row missing'));
          resolve();
        });
      });
      const server = SERVERS.get(serverId);
      if (!server) return reply({ ok: false, error: 'That server does not exist.' });
      server.passcodeHash = passcodeHash;
      console.log(`🔐 Server password ${passcodeHash ? 'set' : 'removed'}: ${serverId}`);
      reply({ ok: true, serverId, isLocked: passcodeHash !== null });
      announceServersChanged();
    } catch (err) {
      console.error('Could not update server password:', err.message);
      reply({ ok: false, error: 'Could not update the password. Please try again.' });
    }
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

// Start accepting connections only once the schema is ready and the server registry is loaded
migrateDatabase((err) => {
  if (err) console.error('🔴 Database migration failed:', err.message);
  loadRegistry((err) => {
    if (err) console.error('🔴 Could not load servers:', err.message);
    console.log(`📚 Loaded ${SERVERS.size} servers.`);
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Chat server running at http://0.0.0.0:${PORT}`);
    });
  });
});