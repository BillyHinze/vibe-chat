import express from 'express';
import { WebSocketServer } from 'ws';
import http from 'http';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey_changeme_in_prod_2025';
const PORT = process.env.PORT || 3000;

// ── Database (simple JSON file) ────────────────────────────────────────────
const dbFile = path.join(__dirname, 'db.json');
const DEFAULT_DB = () => ({
  users: [],
  messages: [],
  rooms: [
    { id: 'general', name: 'general', description: 'Everyone hangs here 🔥', createdAt: Date.now() },
    { id: 'random',  name: 'random',  description: 'Post anything lol',       createdAt: Date.now() },
    { id: 'gaming',  name: 'gaming',  description: 'Gaming talk only',         createdAt: Date.now() },
    { id: 'music',   name: 'music',   description: 'Drop ur fav songs 🎵',     createdAt: Date.now() },
  ]
});

function dbRead() {
  try {
    const raw = fs.readFileSync(dbFile, 'utf8').trim();
    if (!raw) throw new Error('empty');
    return JSON.parse(raw);
  } catch {
    console.warn('⚠️  db.json was missing or invalid — resetting to defaults');
    const fresh = DEFAULT_DB();
    fs.writeFileSync(dbFile, JSON.stringify(fresh, null, 2), 'utf8');
    return fresh;
  }
}
function dbWrite(data) {
  try { fs.writeFileSync(dbFile, JSON.stringify(data, null, 2), 'utf8'); }
  catch (e) { console.error('DB write error:', e); }
}

let db = dbRead();

// ── Express Setup ──────────────────────────────────────────────────────────
const app = express();
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET','POST','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.use(express.json());
app.use((req, res, next) => {
  res.jsonError = (status, msg) => res.status(status).json({ error: msg });
  next();
});

// ── Health check (public, no auth — required for Railway) ─────────────────
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// ── Auth Middleware ────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  const token = header.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────
function sanitizeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    isOwner: !!user.isOwner,
    avatar: user.avatar,
    status: user.status || 'online',
    bio: user.bio || '',
    createdAt: user.createdAt
  };
}
function hydrateMessages(msgs) {
  return msgs.map(m => {
    const user = db.users.find(u => u.id === m.userId);
    const result = {
      ...m,
      user: user ? sanitizeUser(user) : { id: m.userId, username: 'deleted', displayName: 'Deleted User', avatar: '', isOwner: false, status: 'offline', bio: '' }
    };
    if (m.replyTo) {
      const parent = db.messages.find(p => p.id === m.replyTo);
      if (parent) {
        const parentUser = db.users.find(u => u.id === parent.userId);
        result.replyToMsg = {
          ...parent,
          user: parentUser ? sanitizeUser(parentUser) : { displayName: 'Deleted User', username: 'deleted' }
        };
      }
    }
    return result;
  });
}

// ── Auth Routes ────────────────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, displayName } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    if (!/^[a-zA-Z0-9_.-]+$/.test(username)) return res.status(400).json({ error: 'Username: letters, numbers, _ . - only' });
    db = dbRead();
    if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ error: 'Username already taken' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const isOwner = username.toLowerCase() === 'billy';
    const user = {
      id: uuidv4(),
      username: username.toLowerCase(),
      displayName: (displayName?.trim() || username).slice(0, 32),
      password: hashedPassword,
      isOwner,
      avatar: `https://api.dicebear.com/7.x/adventurer/svg?seed=${encodeURIComponent(username)}`,
      status: 'online',
      bio: '',
      createdAt: Date.now()
    };
    db.users.push(user);
    dbWrite(db);
    const token = jwt.sign({ id: user.id, username: user.username, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: sanitizeUser(user) });
  } catch (e) {
    console.error('Signup error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    db = dbRead();
    const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.status(400).json({ error: 'User not found' });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Wrong password' });
    user.status = 'online';
    dbWrite(db);
    const token = jwt.sign({ id: user.id, username: user.username, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: sanitizeUser(user) });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/me', authMiddleware, (req, res) => {
  db = dbRead();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(sanitizeUser(user));
});

// ── User Routes ────────────────────────────────────────────────────────────
app.get('/api/users', authMiddleware, (req, res) => {
  db = dbRead();
  res.json(db.users.map(sanitizeUser));
});
app.patch('/api/users/status', authMiddleware, (req, res) => {
  const { status } = req.body || {};
  const allowed = ['online', 'away', 'dnd', 'offline'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });
  db = dbRead();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.status = status;
  dbWrite(db);
  res.json({ ok: true });
});
app.patch('/api/users/bio', authMiddleware, (req, res) => {
  const { bio } = req.body || {};
  db = dbRead();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.bio = (bio || '').slice(0, 200);
  dbWrite(db);
  res.json({ ok: true });
});
app.patch('/api/users/displayName', authMiddleware, (req, res) => {
  const { displayName } = req.body || {};
  if (!displayName?.trim()) return res.status(400).json({ error: 'Display name required' });
  db = dbRead();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.displayName = displayName.trim().slice(0, 32);
  dbWrite(db);
  res.json({ ok: true, displayName: user.displayName });
});

// ── Room Routes ────────────────────────────────────────────────────────────
app.get('/api/rooms', authMiddleware, (req, res) => {
  db = dbRead();
  res.json(db.rooms);
});
app.post('/api/rooms', authMiddleware, (req, res) => {
  const { name, description } = req.body || {};
  if (!name) return res.status(400).json({ error: 'Room name required' });
  const clean = name.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
  if (!clean) return res.status(400).json({ error: 'Invalid room name' });
  db = dbRead();
  if (db.rooms.find(r => r.id === clean)) return res.status(400).json({ error: 'Room already exists' });
  const room = { id: clean, name: clean, description: (description || '').slice(0, 100), createdBy: req.user.id, createdAt: Date.now() };
  db.rooms.push(room);
  dbWrite(db);
  broadcast({ type: 'room_created', room });
  res.json(room);
});
app.delete('/api/rooms/:roomId', authMiddleware, (req, res) => {
  db = dbRead();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user?.isOwner) return res.status(403).json({ error: 'Owner only' });
  const PROTECTED = ['general', 'random', 'gaming', 'music'];
  if (PROTECTED.includes(req.params.roomId)) return res.status(400).json({ error: 'Cannot delete default channels' });
  db.rooms = db.rooms.filter(r => r.id !== req.params.roomId);
  db.messages = db.messages.filter(m => m.roomId !== req.params.roomId);
  dbWrite(db);
  broadcast({ type: 'room_deleted', roomId: req.params.roomId });
  res.json({ ok: true });
});

// ── Message Routes ─────────────────────────────────────────────────────────
app.get('/api/messages/:roomId', authMiddleware, (req, res) => {
  const { before, limit = 50 } = req.query;
  db = dbRead();
  let msgs = db.messages.filter(m => m.roomId === req.params.roomId && !m.dmKey);
  if (before) msgs = msgs.filter(m => m.createdAt < parseInt(before));
  msgs = msgs.slice(-Math.min(parseInt(limit) || 50, 100));
  res.json(hydrateMessages(msgs));
});

// ── DM Routes ──────────────────────────────────────────────────────────────
app.get('/api/dm/:userId', authMiddleware, (req, res) => {
  db = dbRead();
  const dmKey = [req.user.id, req.params.userId].sort().join(':');
  const msgs = db.messages.filter(m => m.dmKey === dmKey).slice(-100);
  res.json(hydrateMessages(msgs));
});

// ── Search ─────────────────────────────────────────────────────────────────
app.get('/api/search', authMiddleware, (req, res) => {
  const { q, roomId } = req.query;
  if (!q || q.trim().length < 2) return res.status(400).json({ error: 'Query too short' });
  db = dbRead();
  const query = q.toLowerCase();
  let msgs = db.messages.filter(m => !m.dmKey && m.text && m.text.toLowerCase().includes(query));
  if (roomId) msgs = msgs.filter(m => m.roomId === roomId);
  res.json(hydrateMessages(msgs.slice(-30)));
});

// ── Pin Routes ─────────────────────────────────────────────────────────────
app.post('/api/messages/:msgId/pin', authMiddleware, (req, res) => {
  db = dbRead();
  const msg = db.messages.find(m => m.id === req.params.msgId);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  msg.pinned = !msg.pinned;
  dbWrite(db);
  broadcast({ type: 'message_pinned', messageId: msg.id, pinned: msg.pinned, roomId: msg.roomId });
  res.json({ ok: true, pinned: msg.pinned });
});
app.get('/api/rooms/:roomId/pins', authMiddleware, (req, res) => {
  db = dbRead();
  const pins = db.messages.filter(m => m.roomId === req.params.roomId && m.pinned);
  res.json(hydrateMessages(pins));
});

// ── Serve Frontend ─────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ error: 'Frontend not found. Place index.html in the public/ folder.' });
  }
});

// ── Global error handler ───────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── HTTP + WebSocket Server ────────────────────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const clients = new Map();

function broadcast(data, excludeWs = null) {
  const msg = JSON.stringify(data);
  for (const [ws] of clients) {
    if (ws !== excludeWs && ws.readyState === 1) {
      try { ws.send(msg); } catch {}
    }
  }
}
function sendTo(userId, data) {
  const msg = JSON.stringify(data);
  for (const [ws, info] of clients) {
    if (info.userId === userId && ws.readyState === 1) {
      try { ws.send(msg); } catch {}
    }
  }
}

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async (rawData) => {
    let data;
    try { data = JSON.parse(rawData.toString()); }
    catch { return; }

    const clientInfo = clients.get(ws);

    switch (data.type) {
      case 'auth': {
        try {
          const payload = jwt.verify(data.token, JWT_SECRET);
          clients.set(ws, { userId: payload.id, username: payload.username, isOwner: payload.isOwner });
          db = dbRead();
          const user = db.users.find(u => u.id === payload.id);
          if (user) { user.status = 'online'; dbWrite(db); }
          broadcast({ type: 'user_online', userId: payload.id, username: payload.username }, ws);
          const onlineIds = [...new Set([...clients.values()].map(c => c.userId))];
          ws.send(JSON.stringify({ type: 'online_users', userIds: onlineIds }));
          ws.send(JSON.stringify({ type: 'auth_ok' }));
        } catch {
          try { ws.send(JSON.stringify({ type: 'error', message: 'Auth failed' })); } catch {}
          ws.close();
        }
        break;
      }
      case 'message': {
        if (!clientInfo) return;
        const { roomId, text, replyTo } = data;
        if (!text?.trim() || !roomId) return;
        db = dbRead();
        const room = db.rooms.find(r => r.id === roomId);
        if (!room) return;
        const user = db.users.find(u => u.id === clientInfo.userId);
        if (!user) return;
        const msg = {
          id: uuidv4(),
          roomId,
          userId: user.id,
          text: text.trim().slice(0, 2000),
          replyTo: replyTo || null,
          reactions: {},
          edited: false,
          pinned: false,
          createdAt: Date.now()
        };
        db.messages.push(msg);
        dbWrite(db);
        const fullMsg = { ...msg, user: sanitizeUser(user) };
        if (replyTo) {
          const parent = db.messages.find(m => m.id === replyTo);
          if (parent) {
            const parentUser = db.users.find(u => u.id === parent.userId);
            fullMsg.replyToMsg = { ...parent, user: parentUser ? sanitizeUser(parentUser) : null };
          }
        }
        broadcast({ type: 'message', message: fullMsg });
        break;
      }
      case 'edit_message': {
        if (!clientInfo) return;
        db = dbRead();
        const msg = db.messages.find(m => m.id === data.messageId);
        if (!msg || msg.userId !== clientInfo.userId) return;
        if (!data.text?.trim()) return;
        msg.text = data.text.trim().slice(0, 2000);
        msg.edited = true;
        msg.editedAt = Date.now();
        dbWrite(db);
        broadcast({ type: 'message_edited', messageId: msg.id, text: msg.text, editedAt: msg.editedAt });
        break;
      }
      case 'delete_message': {
        if (!clientInfo) return;
        db = dbRead();
        const msg = db.messages.find(m => m.id === data.messageId);
        if (!msg) return;
        if (msg.userId !== clientInfo.userId && !clientInfo.isOwner) return;
        db.messages = db.messages.filter(m => m.id !== data.messageId);
        dbWrite(db);
        broadcast({ type: 'message_deleted', messageId: data.messageId });
        break;
      }
      case 'dm': {
        if (!clientInfo) return;
        const { toUserId, text, replyTo } = data;
        if (!text?.trim() || !toUserId) return;
        db = dbRead();
        const user = db.users.find(u => u.id === clientInfo.userId);
        const toUser = db.users.find(u => u.id === toUserId);
        if (!user || !toUser) return;
        const dmKey = [user.id, toUserId].sort().join(':');
        const msg = {
          id: uuidv4(),
          dmKey,
          userId: user.id,
          toUserId,
          text: text.trim().slice(0, 2000),
          replyTo: replyTo || null,
          reactions: {},
          edited: false,
          createdAt: Date.now()
        };
        db.messages.push(msg);
        dbWrite(db);
        const fullMsg = { ...msg, user: sanitizeUser(user) };
        sendTo(user.id, { type: 'dm', message: fullMsg });
        if (toUserId !== user.id) {
          sendTo(toUserId, { type: 'dm', message: fullMsg, fromUser: sanitizeUser(user) });
        }
        break;
      }
      case 'typing': {
        if (!clientInfo) return;
        broadcast({
          type: 'typing',
          userId: clientInfo.userId,
          username: clientInfo.username,
          roomId: data.roomId,
          isDm: data.isDm,
          toUserId: data.toUserId
        }, ws);
        break;
      }
      case 'reaction': {
        if (!clientInfo) return;
        if (!data.emoji || !data.messageId) return;
        db = dbRead();
        const msg = db.messages.find(m => m.id === data.messageId);
        if (!msg) return;
        if (!msg.reactions) msg.reactions = {};
        if (!msg.reactions[data.emoji]) msg.reactions[data.emoji] = [];
        const idx = msg.reactions[data.emoji].indexOf(clientInfo.userId);
        if (idx === -1) msg.reactions[data.emoji].push(clientInfo.userId);
        else msg.reactions[data.emoji].splice(idx, 1);
        if (msg.reactions[data.emoji].length === 0) delete msg.reactions[data.emoji];
        dbWrite(db);
        broadcast({ type: 'reaction_update', messageId: data.messageId, reactions: msg.reactions });
        break;
      }
      case 'read_receipt': {
        if (!clientInfo) return;
        broadcast({ type: 'read_receipt', userId: clientInfo.userId, roomId: data.roomId, timestamp: Date.now() }, ws);
        break;
      }
      default: break;
    }
  });

  ws.on('close', () => {
    const info = clients.get(ws);
    if (info) {
      clients.delete(ws);
      const stillOnline = [...clients.values()].some(c => c.userId === info.userId);
      if (!stillOnline) {
        db = dbRead();
        const user = db.users.find(u => u.id === info.userId);
        if (user) { user.status = 'offline'; dbWrite(db); }
        broadcast({ type: 'user_offline', userId: info.userId });
      }
    }
  });

  ws.on('error', (err) => console.error('WebSocket error:', err.message));
});

// Keep-alive ping every 30s
const heartbeat = setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);
wss.on('close', () => clearInterval(heartbeat));

server.listen(PORT, () => {
  console.log(`\n🚀 VIBE chat server running at http://localhost:${PORT}`);
  console.log(`📁 Database: ${dbFile}`);
  if (JWT_SECRET === 'supersecretkey_changeme_in_prod_2025') {
    console.log('⚠️  Using default JWT_SECRET — set JWT_SECRET env var in production!\n');
  } else {
    console.log('🔑 JWT Secret: Custom ✓\n');
  }
});
