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
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ═══════════════════════════════════════════════════════════════════
//  CONFIG & CONSTANTS
// ═══════════════════════════════════════════════════════════════════
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey_changeme_in_prod_2025';
const PORT = process.env.PORT || 3000;
const MAX_MSG_LEN = 2000;
const MAX_BIO_LEN = 200;
const MAX_DISPLAY_NAME = 32;
const MAX_ROOM_DESC = 100;
const MAX_MESSAGES_STORED = 5000;       // per room hard cap
const MSG_FETCH_LIMIT = 100;
const OWNER_USERNAME = 'billy';

// XP awards
const XP_PER_MSG        = 5;
const XP_PER_REACTION   = 2;
const XP_PER_EDIT       = 1;
const CREDITS_PER_MSG   = 1;
const CREDITS_PER_LEVEL = 150;
const LEVEL_XP = [0,500,1200,2500,4500,7500,12000,18500,27000,38000,52000,70000,92000,120000,155000];
const LEVEL_NAMES = ['Lurker','Newcomer','Chatter','Regular','Active','Veteran','Elite','Legend','Myth','Icon','Deity','GOAT','Transcendent','Omniscient','The Void'];

// ═══════════════════════════════════════════════════════════════════
//  DATABASE — JSON file persistence + in-memory cache
// ═══════════════════════════════════════════════════════════════════
const dbFile = path.join(__dirname, 'db.json');

function DEFAULT_DB() {
  return {
    users: [],
    messages: [],
    rooms: [
      { id: 'general', name: 'general', description: 'Everyone hangs here 🔥', createdAt: Date.now() },
      { id: 'random',  name: 'random',  description: 'Post anything lol',       createdAt: Date.now() },
      { id: 'gaming',  name: 'gaming',  description: 'Gaming talk only 🎮',     createdAt: Date.now() },
      { id: 'music',   name: 'music',   description: 'Drop ur fav songs 🎵',    createdAt: Date.now() },
    ],
    friendRequests: [],    // { id, fromUserId, toUserId, status: 'pending'|'accepted'|'rejected', createdAt }
    notifications: [],     // { id, userId, type, title, body, data, read, createdAt }
    serverInvites: [],     // { code, serverId, createdBy, createdAt, uses }
    privateServers: [],    // { id, name, desc, privacy, emoji, ownerId, members, channels, inviteCode, createdAt }
    readReceipts: {},      // { msgId: { readBy: [{userId, time}] } }
    reactions: {},         // { msgId: { emoji: [userId,...] } }  (also stored inline on messages for hydration)
    typingCleared: 0,
  };
}

function dbRead() {
  try {
    const raw = fs.readFileSync(dbFile, 'utf8').trim();
    if (!raw) throw new Error('empty');
    const parsed = JSON.parse(raw);
    // Ensure all required top-level keys exist on old DBs
    const defaults = DEFAULT_DB();
    for (const key of Object.keys(defaults)) {
      if (parsed[key] === undefined) parsed[key] = defaults[key];
    }
    return parsed;
  } catch {
    console.warn('⚠️  db.json was missing or invalid — resetting to defaults');
    const fresh = DEFAULT_DB();
    dbWrite(fresh);
    return fresh;
  }
}

function dbWrite(data) {
  try {
    // Trim messages per room to avoid bloat
    const roomIds = new Set(data.rooms.map(r => r.id));
    for (const rid of roomIds) {
      const roomMsgs = data.messages.filter(m => m.roomId === rid && !m.dmKey);
      if (roomMsgs.length > MAX_MESSAGES_STORED) {
        const keep = new Set(roomMsgs.slice(-MAX_MESSAGES_STORED).map(m => m.id));
        data.messages = data.messages.filter(m => m.roomId !== rid || m.dmKey || keep.has(m.id));
      }
    }
    fs.writeFileSync(dbFile, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('DB write error:', e);
  }
}

// ─── Keep one hot copy in memory and write-through ───────────────────────────
let db = dbRead();
const DB = {
  get: () => { db = dbRead(); return db; },
  write: () => dbWrite(db),
  // Convenience: mutate then persist
  save: (mutateFn) => { mutateFn(db); dbWrite(db); },
};

// ═══════════════════════════════════════════════════════════════════
//  EXPRESS APP
// ═══════════════════════════════════════════════════════════════════
const app = express();

app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  methods: ['GET','POST','PATCH','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// Body size limit bumped to accept base64 avatar images (≤8MB)
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));

app.use((req, res, next) => {
  res.jsonError = (status, msg) => res.status(status).json({ error: msg });
  next();
});

// Health check
app.get('/health', (_req, res) => res.json({ ok: true, ts: Date.now(), users: db.users.length }));

// ─── Auth Middleware ─────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function ownerMiddleware(req, res, next) {
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user?.isOwner) return res.status(403).json({ error: 'Owner only' });
  next();
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function sanitizeUser(user) {
  if (!user) return null;
  return {
    id:          user.id,
    username:    user.username,
    displayName: user.displayName,
    isOwner:     !!user.isOwner,
    avatar:      user.avatar || `https://api.dicebear.com/7.x/adventurer/svg?seed=${encodeURIComponent(user.username)}`,
    status:      user.status || 'online',
    bio:         user.bio   || '',
    xp:          user.xp    || 0,
    level:       computeLevel(user.xp || 0),
    credits:     user.credits || 0,
    inventory:   user.inventory || {},
    equipped:    user.equipped  || {},
    stats:       user.stats || { msgsSent: 0, reactionsGiven: 0 },
    streak:      user.streak || 0,
    lastActiveDay: user.lastActiveDay || '',
    friends:     user.friends || [],
    createdAt:   user.createdAt,
  };
}

function computeLevel(xp) {
  let lv = 1;
  for (let i = 1; i < LEVEL_XP.length; i++) {
    if (xp >= LEVEL_XP[i]) lv = i + 1; else break;
  }
  return Math.min(lv, LEVEL_XP.length);
}

function hydrateMessage(m) {
  const user = db.users.find(u => u.id === m.userId);
  const result = {
    ...m,
    reactions: db.reactions?.[m.id] || m.reactions || {},
    user: user ? sanitizeUser(user) : {
      id: m.userId, username: 'deleted', displayName: 'Deleted User',
      avatar: '', isOwner: false, status: 'offline', bio: '',
      xp: 0, level: 1, credits: 0, inventory: {}, equipped: {}, stats: {},
    },
  };
  if (m.replyTo) {
    const parent = db.messages.find(p => p.id === m.replyTo);
    if (parent) {
      const pu = db.users.find(u => u.id === parent.userId);
      result.replyToMsg = {
        ...parent,
        user: pu ? sanitizeUser(pu) : { displayName: 'Deleted User', username: 'deleted' },
      };
    }
  }
  return result;
}

function hydrateMessages(msgs) {
  return msgs.map(hydrateMessage);
}

function pushNotification(userId, notif) {
  const n = {
    id: uuidv4(),
    userId,
    type:      notif.type || 'info',
    title:     notif.title || '',
    body:      notif.body  || '',
    emoji:     notif.emoji || '🔔',
    icon:      notif.icon  || '',
    data:      notif.data  || {},
    read:      false,
    createdAt: Date.now(),
  };
  db.notifications.push(n);
  // Keep notifications manageable per user
  const userNotifs = db.notifications.filter(x => x.userId === userId);
  if (userNotifs.length > 200) {
    const cutoff = userNotifs[0].id;
    const idx = db.notifications.findIndex(x => x.id === cutoff);
    if (idx !== -1) db.notifications.splice(idx, 1);
  }
  DB.write();
  // Push to live client if connected
  sendTo(userId, { type: 'notification', notification: n });
  return n;
}

// ═══════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password, displayName, avatar } = req.body || {};
    if (!username || !password) return res.jsonError(400, 'Username and password required');
    if (username.length < 3)  return res.jsonError(400, 'Username must be at least 3 characters');
    if (password.length < 4)  return res.jsonError(400, 'Password must be at least 4 characters');
    if (!/^[a-zA-Z0-9_.\-]+$/.test(username)) return res.jsonError(400, 'Username: letters, numbers, _ . - only');

    DB.get();
    if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.jsonError(400, 'Username already taken');
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const isOwner = username.toLowerCase() === OWNER_USERNAME;

    // Validate avatar if provided (must be base64 data URL or http URL)
    let safeAvatar = `https://api.dicebear.com/7.x/adventurer/svg?seed=${encodeURIComponent(username)}`;
    if (avatar) {
      if (avatar.startsWith('data:image/') || avatar.startsWith('http')) {
        // For base64 images limit to 8MB
        if (avatar.length < 8 * 1024 * 1024 * 1.37) { // base64 ~37% overhead
          safeAvatar = avatar;
        }
      }
    }

    const user = {
      id:           uuidv4(),
      username:     username.toLowerCase(),
      displayName:  (displayName?.trim() || username).slice(0, MAX_DISPLAY_NAME),
      password:     hashedPassword,
      isOwner,
      avatar:       safeAvatar,
      status:       'online',
      bio:          '',
      xp:           0,
      level:        1,
      credits:      isOwner ? 9999 : 0,
      inventory:    {},
      equipped:     {},
      stats:        { msgsSent: 0, reactionsGiven: 0, pollsCreated: 0, gifsSent: 0 },
      streak:       0,
      lastActiveDay:'',
      friends:      [],   // array of user ids
      createdAt:    Date.now(),
    };

    db.users.push(user);
    DB.write();

    const token = jwt.sign({ id: user.id, username: user.username, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '7d' });

    if (isOwner) {
      console.log(`👑 Owner account created: ${user.username}`);
    }

    // Broadcast to all connected clients that a new user appeared
    broadcast({ type: 'user_joined', user: sanitizeUser(user) });

    res.json({ token, user: sanitizeUser(user) });
  } catch (e) {
    console.error('Signup error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.jsonError(400, 'Username and password required');

    DB.get();
    const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
    if (!user) return res.jsonError(400, 'User not found');

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.jsonError(400, 'Wrong password');

    // Update status & streak
    const today = new Date().toDateString();
    const yest  = new Date(Date.now() - 86400000).toDateString();
    if (user.lastActiveDay !== today) {
      user.streak = user.lastActiveDay === yest ? (user.streak || 0) + 1 : 1;
      user.lastActiveDay = today;
    }
    user.status = 'online';
    DB.write();

    const token = jwt.sign({ id: user.id, username: user.username, isOwner: user.isOwner }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: sanitizeUser(user) });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/me', authMiddleware, (req, res) => {
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  res.json(sanitizeUser(user));
});

// ═══════════════════════════════════════════════════════════════════
//  USER ROUTES
// ═══════════════════════════════════════════════════════════════════
app.get('/api/users', authMiddleware, (req, res) => {
  DB.get();
  res.json(db.users.map(sanitizeUser));
});

app.get('/api/users/:userId', authMiddleware, (req, res) => {
  DB.get();
  const user = db.users.find(u => u.id === req.params.userId);
  if (!user) return res.jsonError(404, 'User not found');
  res.json(sanitizeUser(user));
});

app.patch('/api/users/status', authMiddleware, (req, res) => {
  const { status } = req.body || {};
  const allowed = ['online', 'away', 'dnd', 'offline'];
  if (!allowed.includes(status)) return res.jsonError(400, 'Invalid status');
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  user.status = status;
  DB.write();
  broadcast({ type: 'user_status_update', userId: user.id, status });
  res.json({ ok: true });
});

app.patch('/api/users/bio', authMiddleware, (req, res) => {
  const { bio } = req.body || {};
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  user.bio = (bio || '').slice(0, MAX_BIO_LEN);
  DB.write();
  broadcast({ type: 'user_updated', user: sanitizeUser(user) });
  res.json({ ok: true });
});

app.patch('/api/users/displayName', authMiddleware, (req, res) => {
  const { displayName } = req.body || {};
  if (!displayName?.trim()) return res.jsonError(400, 'Display name required');
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  user.displayName = displayName.trim().slice(0, MAX_DISPLAY_NAME);
  DB.write();
  broadcast({ type: 'user_updated', user: sanitizeUser(user) });
  res.json({ ok: true, displayName: user.displayName });
});

app.patch('/api/users/avatar', authMiddleware, (req, res) => {
  const { avatar } = req.body || {};
  if (!avatar) return res.jsonError(400, 'Avatar required');
  if (!avatar.startsWith('data:image/') && !avatar.startsWith('http')) {
    return res.jsonError(400, 'Invalid avatar format');
  }
  if (avatar.length > 8 * 1024 * 1024 * 1.37) return res.jsonError(400, 'Avatar image too large (max 8MB)');
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  user.avatar = avatar;
  DB.write();
  broadcast({ type: 'user_updated', user: sanitizeUser(user) });
  res.json({ ok: true, avatar: user.avatar });
});

// Full profile patch (displayName + bio + status + avatar in one shot)
app.patch('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    const { displayName, bio, status, avatar } = req.body || {};
    const allowed = ['online', 'away', 'dnd', 'offline'];
    DB.get();
    const user = db.users.find(u => u.id === req.user.id);
    if (!user) return res.jsonError(404, 'User not found');
    if (displayName?.trim()) user.displayName = displayName.trim().slice(0, MAX_DISPLAY_NAME);
    if (bio !== undefined)   user.bio = (bio || '').slice(0, MAX_BIO_LEN);
    if (status && allowed.includes(status)) user.status = status;
    if (avatar) {
      if ((avatar.startsWith('data:image/') || avatar.startsWith('http')) && avatar.length < 8 * 1024 * 1024 * 1.37) {
        user.avatar = avatar;
      }
    }
    DB.write();
    broadcast({ type: 'user_updated', user: sanitizeUser(user) });
    res.json({ ok: true, user: sanitizeUser(user) });
  } catch (e) {
    console.error('Profile update error:', e);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── XP / Credits / Inventory ────────────────────────────────────────────────
app.get('/api/users/me/xp', authMiddleware, (req, res) => {
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  res.json({
    xp:      user.xp      || 0,
    level:   computeLevel(user.xp || 0),
    credits: user.credits || 0,
    stats:   user.stats   || {},
    streak:  user.streak  || 0,
  });
});

app.post('/api/users/me/inventory/equip', authMiddleware, (req, res) => {
  const { slot, itemId } = req.body || {};
  if (!slot || !itemId) return res.jsonError(400, 'slot and itemId required');
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  if (!user.inventory) user.inventory = {};
  if (!user.equipped)  user.equipped  = {};
  if (!user.inventory[itemId]) return res.jsonError(403, 'You do not own this item');
  user.equipped[slot] = itemId;
  DB.write();
  broadcast({ type: 'user_updated', user: sanitizeUser(user) });
  res.json({ ok: true });
});

app.post('/api/users/me/inventory/unequip', authMiddleware, (req, res) => {
  const { slot } = req.body || {};
  if (!slot) return res.jsonError(400, 'slot required');
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  if (!user.equipped) user.equipped = {};
  delete user.equipped[slot];
  DB.write();
  broadcast({ type: 'user_updated', user: sanitizeUser(user) });
  res.json({ ok: true });
});

app.post('/api/shop/buy', authMiddleware, (req, res) => {
  const { itemId, cost } = req.body || {};
  if (!itemId || cost === undefined) return res.jsonError(400, 'itemId and cost required');
  if (typeof cost !== 'number' || cost < 0) return res.jsonError(400, 'Invalid cost');
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  if (!user.inventory) user.inventory = {};
  if (user.inventory[itemId]) return res.jsonError(400, 'Already owned');
  const userCredits = user.credits || 0;
  if (userCredits < cost) return res.jsonError(402, `Not enough credits (need ${cost}, have ${userCredits})`);
  user.credits = userCredits - cost;
  user.inventory[itemId] = true;
  DB.write();
  res.json({ ok: true, credits: user.credits, inventory: user.inventory });
});

// ═══════════════════════════════════════════════════════════════════
//  FRIENDS ROUTES
// ═══════════════════════════════════════════════════════════════════
app.post('/api/friends/request', authMiddleware, (req, res) => {
  const { toUserId } = req.body || {};
  if (!toUserId) return res.jsonError(400, 'toUserId required');
  if (toUserId === req.user.id) return res.jsonError(400, 'Cannot add yourself');
  DB.get();
  const toUser = db.users.find(u => u.id === toUserId);
  if (!toUser) return res.jsonError(404, 'User not found');
  const fromUser = db.users.find(u => u.id === req.user.id);
  if (!fromUser) return res.jsonError(404, 'Sender not found');
  // Check already friends
  if ((fromUser.friends || []).includes(toUserId)) return res.jsonError(400, 'Already friends');
  // Check already pending
  const existing = db.friendRequests.find(
    r => r.fromUserId === req.user.id && r.toUserId === toUserId && r.status === 'pending'
  );
  if (existing) return res.jsonError(400, 'Request already sent');
  const request = {
    id: uuidv4(), fromUserId: req.user.id, toUserId, status: 'pending', createdAt: Date.now(),
  };
  db.friendRequests.push(request);
  DB.write();
  // Notify the target user
  pushNotification(toUserId, {
    type: 'friend_request', emoji: '👥',
    title: `Friend request from ${fromUser.displayName}`,
    body: 'Check your Friends tab!',
    icon: fromUser.avatar || '',
    data: { fromUserId: req.user.id, requestId: request.id },
  });
  sendTo(toUserId, { type: 'friend_request', requestId: request.id, fromUser: sanitizeUser(fromUser) });
  res.json({ ok: true, requestId: request.id });
});

app.post('/api/friends/accept', authMiddleware, (req, res) => {
  const { requestId } = req.body || {};
  if (!requestId) return res.jsonError(400, 'requestId required');
  DB.get();
  const request = db.friendRequests.find(r => r.id === requestId && r.toUserId === req.user.id && r.status === 'pending');
  if (!request) return res.jsonError(404, 'Friend request not found');
  request.status = 'accepted';
  // Add to both users' friends list
  const me = db.users.find(u => u.id === req.user.id);
  const them = db.users.find(u => u.id === request.fromUserId);
  if (!me || !them) return res.jsonError(404, 'User not found');
  if (!me.friends)   me.friends   = [];
  if (!them.friends) them.friends = [];
  if (!me.friends.includes(them.id))   me.friends.push(them.id);
  if (!them.friends.includes(me.id))   them.friends.push(me.id);
  DB.write();
  // Notify the requester
  pushNotification(them.id, {
    type: 'friend_accepted', emoji: '🤝',
    title: `${me.displayName} accepted your friend request!`,
    body: 'You can now DM each other 🎉',
    icon: me.avatar || '',
    data: { userId: me.id },
  });
  sendTo(them.id, { type: 'friend_accept', fromUser: sanitizeUser(me) });
  res.json({ ok: true, friend: sanitizeUser(them) });
});

app.post('/api/friends/reject', authMiddleware, (req, res) => {
  const { requestId } = req.body || {};
  if (!requestId) return res.jsonError(400, 'requestId required');
  DB.get();
  const request = db.friendRequests.find(r => r.id === requestId && r.toUserId === req.user.id && r.status === 'pending');
  if (!request) return res.jsonError(404, 'Friend request not found');
  request.status = 'rejected';
  DB.write();
  res.json({ ok: true });
});

app.delete('/api/friends/:userId', authMiddleware, (req, res) => {
  DB.get();
  const me   = db.users.find(u => u.id === req.user.id);
  const them = db.users.find(u => u.id === req.params.userId);
  if (!me)   return res.jsonError(404, 'User not found');
  if (!them) return res.jsonError(404, 'Target user not found');
  me.friends   = (me.friends   || []).filter(id => id !== them.id);
  them.friends = (them.friends || []).filter(id => id !== me.id);
  // Also mark any accepted requests as removed
  db.friendRequests.forEach(r => {
    if ((r.fromUserId === me.id && r.toUserId === them.id) ||
        (r.fromUserId === them.id && r.toUserId === me.id)) {
      r.status = 'removed';
    }
  });
  DB.write();
  sendTo(them.id, { type: 'friend_removed', userId: me.id });
  res.json({ ok: true });
});

app.get('/api/friends', authMiddleware, (req, res) => {
  DB.get();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.jsonError(404, 'User not found');
  const friendIds = user.friends || [];
  const friends = friendIds.map(id => db.users.find(u => u.id === id)).filter(Boolean).map(sanitizeUser);
  // Pending incoming
  const incoming = db.friendRequests
    .filter(r => r.toUserId === req.user.id && r.status === 'pending')
    .map(r => {
      const from = db.users.find(u => u.id === r.fromUserId);
      return { requestId: r.id, user: from ? sanitizeUser(from) : null, createdAt: r.createdAt };
    }).filter(r => r.user);
  // Pending sent
  const sent = db.friendRequests
    .filter(r => r.fromUserId === req.user.id && r.status === 'pending')
    .map(r => {
      const to = db.users.find(u => u.id === r.toUserId);
      return { requestId: r.id, user: to ? sanitizeUser(to) : null, createdAt: r.createdAt };
    }).filter(r => r.user);
  res.json({ friends, incoming, sent });
});

// ═══════════════════════════════════════════════════════════════════
//  NOTIFICATION ROUTES
// ═══════════════════════════════════════════════════════════════════
app.get('/api/notifications', authMiddleware, (req, res) => {
  DB.get();
  const notifs = db.notifications
    .filter(n => n.userId === req.user.id)
    .slice(-100)
    .reverse();
  res.json(notifs);
});

app.post('/api/notifications/read', authMiddleware, (req, res) => {
  const { notifId } = req.body || {};
  DB.get();
  if (notifId) {
    const n = db.notifications.find(x => x.id === notifId && x.userId === req.user.id);
    if (n) n.read = true;
  } else {
    db.notifications.filter(n => n.userId === req.user.id).forEach(n => { n.read = true; });
  }
  DB.write();
  res.json({ ok: true });
});

app.delete('/api/notifications/:notifId', authMiddleware, (req, res) => {
  DB.get();
  const before = db.notifications.length;
  db.notifications = db.notifications.filter(n => !(n.id === req.params.notifId && n.userId === req.user.id));
  DB.write();
  res.json({ ok: true, deleted: before - db.notifications.length });
});

// ═══════════════════════════════════════════════════════════════════
//  ROOM ROUTES
// ═══════════════════════════════════════════════════════════════════
const PROTECTED_ROOMS = ['general', 'random', 'gaming', 'music'];

app.get('/api/rooms', authMiddleware, (req, res) => {
  DB.get();
  res.json(db.rooms);
});

app.post('/api/rooms', authMiddleware, (req, res) => {
  const { name, description } = req.body || {};
  if (!name) return res.jsonError(400, 'Room name required');
  const clean = name.toLowerCase()
    .replace(/[^a-z0-9\-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  if (!clean || clean.length < 1) return res.jsonError(400, 'Invalid room name');
  if (clean.length > 32) return res.jsonError(400, 'Room name too long (max 32)');
  DB.get();
  if (db.rooms.find(r => r.id === clean)) return res.jsonError(400, 'Room already exists');
  const room = {
    id: clean, name: clean,
    description: (description || '').slice(0, MAX_ROOM_DESC),
    createdBy: req.user.id,
    createdAt: Date.now(),
  };
  db.rooms.push(room);
  DB.write();
  broadcast({ type: 'room_created', room });
  // Notify all online users
  const creator = db.users.find(u => u.id === req.user.id);
  for (const [, info] of clients) {
    if (info.userId !== req.user.id) {
      pushNotification(info.userId, {
        type: 'room_created', emoji: '🎉',
        title: `New channel: #${clean}`,
        body: `Created by ${creator?.displayName || 'someone'}`,
        data: { roomId: clean },
      });
    }
  }
  res.json(room);
});

app.delete('/api/rooms/:roomId', authMiddleware, ownerMiddleware, (req, res) => {
  const rid = req.params.roomId;
  if (PROTECTED_ROOMS.includes(rid)) return res.jsonError(400, 'Cannot delete default channels');
  DB.get();
  if (!db.rooms.find(r => r.id === rid)) return res.jsonError(404, 'Room not found');
  db.rooms    = db.rooms.filter(r => r.id !== rid);
  db.messages = db.messages.filter(m => m.roomId !== rid);
  DB.write();
  broadcast({ type: 'room_deleted', roomId: rid });
  res.json({ ok: true });
});

app.patch('/api/rooms/:roomId', authMiddleware, ownerMiddleware, (req, res) => {
  const { description } = req.body || {};
  DB.get();
  const room = db.rooms.find(r => r.id === req.params.roomId);
  if (!room) return res.jsonError(404, 'Room not found');
  if (description !== undefined) room.description = description.slice(0, MAX_ROOM_DESC);
  DB.write();
  broadcast({ type: 'room_updated', room });
  res.json(room);
});

// ═══════════════════════════════════════════════════════════════════
//  MESSAGE ROUTES
// ═══════════════════════════════════════════════════════════════════
app.get('/api/messages/:roomId', authMiddleware, (req, res) => {
  const { before, limit = 50 } = req.query;
  DB.get();
  if (!db.rooms.find(r => r.id === req.params.roomId)) return res.jsonError(404, 'Room not found');
  let msgs = db.messages.filter(m => m.roomId === req.params.roomId && !m.dmKey);
  if (before) msgs = msgs.filter(m => m.createdAt < parseInt(before));
  const cap = Math.min(parseInt(limit) || 50, MSG_FETCH_LIMIT);
  msgs = msgs.slice(-cap);
  res.json(hydrateMessages(msgs));
});

// ═══════════════════════════════════════════════════════════════════
//  DM ROUTES
// ═══════════════════════════════════════════════════════════════════
app.get('/api/dm/:userId', authMiddleware, (req, res) => {
  const { before, limit = 100 } = req.query;
  DB.get();
  // Block DMs if not friends (unless owner)
  const me = db.users.find(u => u.id === req.user.id);
  const them = db.users.find(u => u.id === req.params.userId);
  if (!them) return res.jsonError(404, 'User not found');
  const areFriends = (me?.friends || []).includes(them.id) || me?.isOwner;
  if (!areFriends) return res.jsonError(403, 'You must be friends to view DMs');
  const dmKey = [req.user.id, req.params.userId].sort().join(':');
  let msgs = db.messages.filter(m => m.dmKey === dmKey);
  if (before) msgs = msgs.filter(m => m.createdAt < parseInt(before));
  msgs = msgs.slice(-Math.min(parseInt(limit) || 100, MSG_FETCH_LIMIT));
  res.json(hydrateMessages(msgs));
});

// ═══════════════════════════════════════════════════════════════════
//  SEARCH
// ═══════════════════════════════════════════════════════════════════
app.get('/api/search', authMiddleware, (req, res) => {
  const { q, roomId } = req.query;
  if (!q || q.trim().length < 2) return res.jsonError(400, 'Query too short (min 2 chars)');
  DB.get();
  const query = q.toLowerCase();
  let msgs = db.messages.filter(m => !m.dmKey && m.text && m.text.toLowerCase().includes(query));
  if (roomId) msgs = msgs.filter(m => m.roomId === roomId);
  res.json(hydrateMessages(msgs.slice(-30)));
});

// ═══════════════════════════════════════════════════════════════════
//  PIN ROUTES
// ═══════════════════════════════════════════════════════════════════
app.post('/api/messages/:msgId/pin', authMiddleware, (req, res) => {
  DB.get();
  const me = db.users.find(u => u.id === req.user.id);
  // Allow pinning if user is owner or the message is in a room (not DM)
  const msg = db.messages.find(m => m.id === req.params.msgId);
  if (!msg) return res.jsonError(404, 'Message not found');
  if (!me?.isOwner && msg.userId !== req.user.id) return res.jsonError(403, 'Cannot pin others\' messages (owner only)');
  msg.pinned = !msg.pinned;
  DB.write();
  broadcast({ type: 'message_pinned', messageId: msg.id, pinned: msg.pinned, roomId: msg.roomId });
  res.json({ ok: true, pinned: msg.pinned });
});

app.get('/api/rooms/:roomId/pins', authMiddleware, (req, res) => {
  DB.get();
  const pins = db.messages.filter(m => m.roomId === req.params.roomId && m.pinned && !m.dmKey);
  res.json(hydrateMessages(pins));
});

// ═══════════════════════════════════════════════════════════════════
//  PRIVATE SERVERS
// ═══════════════════════════════════════════════════════════════════
app.get('/api/servers', authMiddleware, (req, res) => {
  DB.get();
  const servers = db.privateServers.filter(s => s.members.includes(req.user.id));
  res.json(servers);
});

app.post('/api/servers', authMiddleware, (req, res) => {
  const { name, description, privacy, emoji } = req.body || {};
  if (!name?.trim()) return res.jsonError(400, 'Server name required');
  DB.get();
  const inviteCode = crypto.randomBytes(3).toString('hex').toUpperCase();
  const server = {
    id:          uuidv4(),
    name:        name.trim().slice(0, 50),
    desc:        (description || '').slice(0, 200),
    privacy:     privacy === 'private' ? 'private' : 'public',
    emoji:       emoji || '🌐',
    ownerId:     req.user.id,
    members:     [req.user.id],
    channels:    ['general', 'chat', 'off-topic'],
    inviteCode,
    createdAt:   Date.now(),
  };
  db.privateServers.push(server);
  DB.write();
  res.json(server);
});

app.post('/api/servers/join', authMiddleware, (req, res) => {
  const { code } = req.body || {};
  if (!code) return res.jsonError(400, 'Invite code required');
  DB.get();
  const server = db.privateServers.find(s => s.inviteCode === code.toUpperCase());
  if (!server) return res.jsonError(404, 'Invalid invite code');
  if (!server.members.includes(req.user.id)) {
    server.members.push(req.user.id);
    DB.write();
    const user = db.users.find(u => u.id === req.user.id);
    // Notify all members
    server.members.filter(id => id !== req.user.id).forEach(memberId => {
      sendTo(memberId, { type: 'server_member_joined', serverId: server.id, user: sanitizeUser(user) });
    });
  }
  res.json(server);
});

app.delete('/api/servers/:serverId/leave', authMiddleware, (req, res) => {
  DB.get();
  const server = db.privateServers.find(s => s.id === req.params.serverId);
  if (!server) return res.jsonError(404, 'Server not found');
  if (!server.members.includes(req.user.id)) return res.jsonError(400, 'Not a member');
  if (server.ownerId === req.user.id) {
    // Owner deletes server
    db.privateServers = db.privateServers.filter(s => s.id !== server.id);
    server.members.forEach(id => sendTo(id, { type: 'server_deleted', serverId: server.id }));
  } else {
    server.members = server.members.filter(id => id !== req.user.id);
    server.members.forEach(id => sendTo(id, { type: 'server_member_left', serverId: server.id, userId: req.user.id }));
  }
  DB.write();
  res.json({ ok: true });
});

app.get('/api/servers/:serverId', authMiddleware, (req, res) => {
  DB.get();
  const server = db.privateServers.find(s => s.id === req.params.serverId);
  if (!server) return res.jsonError(404, 'Server not found');
  if (!server.members.includes(req.user.id)) return res.jsonError(403, 'Not a member');
  const memberUsers = server.members.map(id => db.users.find(u => u.id === id)).filter(Boolean).map(sanitizeUser);
  res.json({ ...server, memberUsers });
});

// Server messages (stored in db.messages with a serverId field)
app.get('/api/servers/:serverId/messages/:channel', authMiddleware, (req, res) => {
  const { before, limit = 50 } = req.query;
  DB.get();
  const server = db.privateServers.find(s => s.id === req.params.serverId);
  if (!server) return res.jsonError(404, 'Server not found');
  if (!server.members.includes(req.user.id)) return res.jsonError(403, 'Not a member');
  let msgs = db.messages.filter(m => m.serverId === req.params.serverId && m.serverChannel === req.params.channel);
  if (before) msgs = msgs.filter(m => m.createdAt < parseInt(before));
  msgs = msgs.slice(-Math.min(parseInt(limit) || 50, MSG_FETCH_LIMIT));
  res.json(hydrateMessages(msgs));
});

// ═══════════════════════════════════════════════════════════════════
//  REACTIONS via REST (also handled over WS)
// ═══════════════════════════════════════════════════════════════════
app.post('/api/messages/:msgId/react', authMiddleware, (req, res) => {
  const { emoji } = req.body || {};
  if (!emoji) return res.jsonError(400, 'emoji required');
  DB.get();
  const msg = db.messages.find(m => m.id === req.params.msgId);
  if (!msg) return res.jsonError(404, 'Message not found');
  if (!db.reactions) db.reactions = {};
  if (!db.reactions[msg.id]) db.reactions[msg.id] = {};
  if (!db.reactions[msg.id][emoji]) db.reactions[msg.id][emoji] = [];
  const idx = db.reactions[msg.id][emoji].indexOf(req.user.id);
  if (idx === -1) {
    db.reactions[msg.id][emoji].push(req.user.id);
  } else {
    db.reactions[msg.id][emoji].splice(idx, 1);
    if (!db.reactions[msg.id][emoji].length) delete db.reactions[msg.id][emoji];
  }
  DB.write();
  // Award XP to user who received reaction (not the reactor)
  if (idx === -1) {
    const msgOwner = db.users.find(u => u.id === msg.userId);
    if (msgOwner && msgOwner.id !== req.user.id) {
      giveXP(msgOwner, XP_PER_REACTION);
    }
    const reactor = db.users.find(u => u.id === req.user.id);
    if (reactor) giveXP(reactor, 1);
  }
  broadcast({ type: 'reaction_update', messageId: msg.id, reactions: db.reactions[msg.id] });
  res.json({ ok: true, reactions: db.reactions[msg.id] });
});

// ═══════════════════════════════════════════════════════════════════
//  XP HELPER (server-side authoritative XP granting)
// ═══════════════════════════════════════════════════════════════════
function giveXP(user, amount) {
  const before = computeLevel(user.xp || 0);
  user.xp = (user.xp || 0) + amount;
  user.credits = (user.credits || 0) + Math.floor(amount / XP_PER_MSG) * CREDITS_PER_MSG;
  const after = computeLevel(user.xp);
  user.level = after;
  if (after > before) {
    user.credits = (user.credits || 0) + CREDITS_PER_LEVEL;
    sendTo(user.id, { type: 'level_up', newLevel: after, levelName: LEVEL_NAMES[after - 1] || '', credits: user.credits });
    pushNotification(user.id, {
      type: 'level_up', emoji: '🎉',
      title: `Level Up! You're now Level ${after}!`,
      body: `${LEVEL_NAMES[after - 1] || ''} — +${CREDITS_PER_LEVEL} credits earned!`,
      data: { level: after },
    });
  }
  // Broadcast updated user info
  broadcast({ type: 'user_updated', user: sanitizeUser(user) });
}

// ═══════════════════════════════════════════════════════════════════
//  STATIC FILE SERVING
// ═══════════════════════════════════════════════════════════════════
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'Not found' });
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) res.sendFile(indexPath);
  else res.status(404).json({ error: 'Frontend not found. Place index.html in the public/ folder.' });
});

// Global error handler
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ═══════════════════════════════════════════════════════════════════
//  HTTP + WEBSOCKET SERVER
// ═══════════════════════════════════════════════════════════════════
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

// clients: Map<WebSocket, { userId, username, isOwner, rooms: Set<string> }>
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

function broadcastToRoom(roomId, data, excludeWs = null) {
  const msg = JSON.stringify(data);
  for (const [ws, info] of clients) {
    if (ws !== excludeWs && ws.readyState === 1 && info.rooms?.has(roomId)) {
      try { ws.send(msg); } catch {}
    }
  }
}

// ═══════════════════════════════════════════════════════════════════
//  WEBSOCKET MESSAGE HANDLER
// ═══════════════════════════════════════════════════════════════════
wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async (rawData) => {
    let data;
    try { data = JSON.parse(rawData.toString()); } catch { return; }

    const clientInfo = clients.get(ws);

    // ── AUTH ──────────────────────────────────────────────────────
    if (data.type === 'auth') {
      try {
        const payload = jwt.verify(data.token, JWT_SECRET);
        DB.get();
        const user = db.users.find(u => u.id === payload.id);
        if (!user) { ws.close(); return; }

        // Update streak on auth
        const today = new Date().toDateString();
        const yest  = new Date(Date.now() - 86400000).toDateString();
        if (user.lastActiveDay !== today) {
          user.streak = user.lastActiveDay === yest ? (user.streak || 0) + 1 : 1;
          user.lastActiveDay = today;
        }
        user.status = 'online';
        DB.write();

        clients.set(ws, {
          userId:   payload.id,
          username: payload.username,
          isOwner:  payload.isOwner,
          rooms:    new Set(),
        });

        broadcast({ type: 'user_online', userId: payload.id, username: payload.username, status: 'online' }, ws);

        const onlineIds = [...new Set([...clients.values()].map(c => c.userId))];
        ws.send(JSON.stringify({ type: 'online_users', userIds: onlineIds }));
        ws.send(JSON.stringify({ type: 'auth_ok', user: sanitizeUser(user) }));
      } catch {
        try { ws.send(JSON.stringify({ type: 'error', message: 'Auth failed' })); } catch {}
        ws.close();
      }
      return;
    }

    // All further messages require auth
    if (!clientInfo) {
      try { ws.send(JSON.stringify({ type: 'error', message: 'Not authenticated' })); } catch {}
      return;
    }

    switch (data.type) {

      // ── CHANNEL MESSAGE ─────────────────────────────────────────
      case 'message': {
        const { roomId, text, replyTo } = data;
        if (!text?.trim() || !roomId) return;
        if (text.length > MAX_MSG_LEN) return;
        DB.get();
        const room = db.rooms.find(r => r.id === roomId);
        if (!room) return;
        const user = db.users.find(u => u.id === clientInfo.userId);
        if (!user) return;

        const msg = {
          id:        uuidv4(),
          roomId,
          userId:    user.id,
          text:      text.trim(),
          replyTo:   replyTo || null,
          reactions: {},
          edited:    false,
          pinned:    false,
          createdAt: Date.now(),
        };

        db.messages.push(msg);
        // Grant XP server-side
        user.stats = user.stats || {};
        user.stats.msgsSent = (user.stats.msgsSent || 0) + 1;
        giveXP(user, XP_PER_MSG);
        DB.write();

        const fullMsg = hydrateMessage(msg);
        broadcast({ type: 'message', message: fullMsg });

        // Notify users not currently in this room
        for (const [, info] of clients) {
          if (info.userId !== clientInfo.userId && !info.rooms?.has(roomId)) {
            const notifUser = db.users.find(u => u.id === info.userId);
            if (notifUser) {
              pushNotification(info.userId, {
                type: 'new_message', emoji: '💬',
                title: `#${roomId} — ${user.displayName}`,
                body:  text.slice(0, 80),
                icon:  user.avatar || '',
                data:  { roomId },
              });
            }
          }
        }
        break;
      }

      // ── SERVER CHANNEL MESSAGE ──────────────────────────────────
      case 'server_message': {
        const { serverId, channel, text, replyTo } = data;
        if (!text?.trim() || !serverId || !channel) return;
        if (text.length > MAX_MSG_LEN) return;
        DB.get();
        const srv = db.privateServers.find(s => s.id === serverId);
        if (!srv || !srv.members.includes(clientInfo.userId)) return;
        const user = db.users.find(u => u.id === clientInfo.userId);
        if (!user) return;

        const msg = {
          id:            uuidv4(),
          serverId,
          serverChannel: channel,
          userId:        user.id,
          text:          text.trim(),
          replyTo:       replyTo || null,
          reactions:     {},
          edited:        false,
          pinned:        false,
          createdAt:     Date.now(),
        };

        db.messages.push(msg);
        user.stats = user.stats || {};
        user.stats.msgsSent = (user.stats.msgsSent || 0) + 1;
        giveXP(user, XP_PER_MSG);
        DB.write();

        const fullMsg = hydrateMessage(msg);
        // Broadcast to all server members online
        for (const [, info] of clients) {
          if (srv.members.includes(info.userId)) {
            sendTo(info.userId, { type: 'server_message', message: fullMsg });
          }
        }
        break;
      }

      // ── EDIT MESSAGE ────────────────────────────────────────────
      case 'edit_message': {
        if (!data.messageId || !data.text?.trim()) return;
        DB.get();
        const msg = db.messages.find(m => m.id === data.messageId);
        if (!msg || msg.userId !== clientInfo.userId) return;
        msg.text     = data.text.trim().slice(0, MAX_MSG_LEN);
        msg.edited   = true;
        msg.editedAt = Date.now();
        const user = db.users.find(u => u.id === clientInfo.userId);
        if (user) giveXP(user, XP_PER_EDIT);
        DB.write();
        broadcast({ type: 'message_edited', messageId: msg.id, text: msg.text, editedAt: msg.editedAt });
        break;
      }

      // ── DELETE MESSAGE ──────────────────────────────────────────
      case 'delete_message': {
        if (!data.messageId) return;
        DB.get();
        const msg = db.messages.find(m => m.id === data.messageId);
        if (!msg) return;
        if (msg.userId !== clientInfo.userId && !clientInfo.isOwner) return;
        db.messages = db.messages.filter(m => m.id !== data.messageId);
        if (db.reactions?.[data.messageId]) delete db.reactions[data.messageId];
        DB.write();
        broadcast({ type: 'message_deleted', messageId: data.messageId });
        break;
      }

      // ── DIRECT MESSAGE ──────────────────────────────────────────
      case 'dm': {
        const { toUserId, text, replyTo } = data;
        if (!text?.trim() || !toUserId) return;
        if (text.length > MAX_MSG_LEN) return;
        DB.get();
        const user   = db.users.find(u => u.id === clientInfo.userId);
        const toUser = db.users.find(u => u.id === toUserId);
        if (!user || !toUser) return;

        // Enforce friend-only DMs (bypass for owner)
        const areFriends = (user.friends || []).includes(toUserId) || user.isOwner;
        if (!areFriends) {
          try { ws.send(JSON.stringify({ type: 'error', message: 'Add this person as a friend before DMing!' })); } catch {}
          return;
        }

        const dmKey = [user.id, toUserId].sort().join(':');
        const msg = {
          id:        uuidv4(),
          dmKey,
          userId:    user.id,
          toUserId,
          text:      text.trim(),
          replyTo:   replyTo || null,
          reactions: {},
          edited:    false,
          createdAt: Date.now(),
        };

        db.messages.push(msg);
        user.stats = user.stats || {};
        user.stats.msgsSent = (user.stats.msgsSent || 0) + 1;
        giveXP(user, XP_PER_MSG);
        DB.write();

        const fullMsg = hydrateMessage(msg);
        sendTo(user.id,   { type: 'dm', message: fullMsg });
        if (toUserId !== user.id) {
          sendTo(toUserId, { type: 'dm', message: fullMsg, fromUser: sanitizeUser(user) });
          // In-app notification if receiver is not currently looking at this DM
          pushNotification(toUserId, {
            type: 'dm', emoji: '💬',
            title: `💬 ${user.displayName} DMed you`,
            body:  text.slice(0, 80),
            icon:  user.avatar || '',
            data:  { dmUserId: user.id },
          });
        }
        break;
      }

      // ── TYPING ──────────────────────────────────────────────────
      case 'typing': {
        broadcast({
          type:      'typing',
          userId:    clientInfo.userId,
          username:  clientInfo.username,
          roomId:    data.roomId,
          isDm:      data.isDm,
          toUserId:  data.toUserId,
          serverId:  data.serverId,
        }, ws);
        break;
      }

      // ── REACTION (over WS) ───────────────────────────────────────
      case 'reaction': {
        if (!data.emoji || !data.messageId) return;
        DB.get();
        const msg = db.messages.find(m => m.id === data.messageId);
        if (!msg) return;
        if (!db.reactions) db.reactions = {};
        if (!db.reactions[msg.id]) db.reactions[msg.id] = {};
        if (!db.reactions[msg.id][data.emoji]) db.reactions[msg.id][data.emoji] = [];
        const idx = db.reactions[msg.id][data.emoji].indexOf(clientInfo.userId);
        if (idx === -1) {
          db.reactions[msg.id][data.emoji].push(clientInfo.userId);
          // Give XP to message owner & reactor
          const reactor = db.users.find(u => u.id === clientInfo.userId);
          const owner   = db.users.find(u => u.id === msg.userId);
          if (reactor) {
            reactor.stats = reactor.stats || {};
            reactor.stats.reactionsGiven = (reactor.stats.reactionsGiven || 0) + 1;
            giveXP(reactor, 1);
          }
          if (owner && owner.id !== clientInfo.userId) giveXP(owner, XP_PER_REACTION);
        } else {
          db.reactions[msg.id][data.emoji].splice(idx, 1);
          if (!db.reactions[msg.id][data.emoji].length) delete db.reactions[msg.id][data.emoji];
        }
        DB.write();
        broadcast({ type: 'reaction_update', messageId: data.messageId, reactions: db.reactions[data.messageId] || {} });
        break;
      }

      // ── READ RECEIPT ────────────────────────────────────────────
      case 'read_receipt': {
        if (!data.roomId) return;
        DB.get();
        // Mark the latest message in this room as read by this user
        const roomMsgs = db.messages.filter(m => m.roomId === data.roomId && !m.dmKey);
        if (!roomMsgs.length) return;
        const lastMsg = roomMsgs[roomMsgs.length - 1];
        if (!db.readReceipts) db.readReceipts = {};
        if (!db.readReceipts[lastMsg.id]) db.readReceipts[lastMsg.id] = { readBy: [] };
        const rr = db.readReceipts[lastMsg.id];
        if (!rr.readBy.find(r => r.userId === clientInfo.userId)) {
          rr.readBy.push({ userId: clientInfo.userId, time: Date.now() });
        }
        DB.write();
        broadcast({
          type:      'read_receipt',
          userId:    clientInfo.userId,
          roomId:    data.roomId,
          msgId:     lastMsg.id,
          timestamp: Date.now(),
        }, ws);
        break;
      }

      // ── USER JOINS / LEAVES ROOM (for targeted broadcasts) ──────
      case 'join_room': {
        if (data.roomId && clientInfo.rooms) clientInfo.rooms.add(data.roomId);
        break;
      }
      case 'leave_room': {
        if (data.roomId && clientInfo.rooms) clientInfo.rooms.delete(data.roomId);
        break;
      }

      // ── FRIEND REQUEST (over WS) ─────────────────────────────────
      case 'friend_request': {
        if (!data.toUserId) return;
        DB.get();
        const fromUser = db.users.find(u => u.id === clientInfo.userId);
        const toUser   = db.users.find(u => u.id === data.toUserId);
        if (!fromUser || !toUser) return;
        if ((fromUser.friends || []).includes(data.toUserId)) return;
        const existing = db.friendRequests.find(
          r => r.fromUserId === clientInfo.userId && r.toUserId === data.toUserId && r.status === 'pending'
        );
        if (existing) return;
        const request = { id: uuidv4(), fromUserId: clientInfo.userId, toUserId: data.toUserId, status: 'pending', createdAt: Date.now() };
        db.friendRequests.push(request);
        DB.write();
        sendTo(data.toUserId, { type: 'friend_request', requestId: request.id, fromUser: sanitizeUser(fromUser) });
        pushNotification(data.toUserId, {
          type: 'friend_request', emoji: '👥',
          title: `Friend request from ${fromUser.displayName}`,
          body: 'Check your Friends tab!',
          icon: fromUser.avatar || '',
          data: { fromUserId: clientInfo.userId, requestId: request.id },
        });
        break;
      }

      // ── FRIEND ACCEPT (over WS) ──────────────────────────────────
      case 'friend_accept': {
        if (!data.requestId) return;
        DB.get();
        const request = db.friendRequests.find(r => r.id === data.requestId && r.toUserId === clientInfo.userId && r.status === 'pending');
        if (!request) return;
        request.status = 'accepted';
        const me   = db.users.find(u => u.id === clientInfo.userId);
        const them = db.users.find(u => u.id === request.fromUserId);
        if (!me || !them) return;
        if (!me.friends)   me.friends   = [];
        if (!them.friends) them.friends = [];
        if (!me.friends.includes(them.id))   me.friends.push(them.id);
        if (!them.friends.includes(me.id))   them.friends.push(me.id);
        DB.write();
        sendTo(them.id, { type: 'friend_accept', fromUser: sanitizeUser(me) });
        sendTo(me.id,   { type: 'friend_accept', fromUser: sanitizeUser(them) });
        pushNotification(them.id, {
          type: 'friend_accepted', emoji: '🤝',
          title: `${me.displayName} accepted your friend request!`,
          body: 'You can now DM each other 🎉',
          icon: me.avatar || '',
          data: { userId: me.id },
        });
        break;
      }

      // ── POLL VOTE ────────────────────────────────────────────────
      case 'poll_vote': {
        if (!data.messageId || data.optionIndex === undefined) return;
        DB.get();
        const msg = db.messages.find(m => m.id === data.messageId);
        if (!msg || !msg.text?.startsWith('[poll:')) return;
        try {
          const poll = JSON.parse(msg.text.slice(6, -1));
          poll.options.forEach((opt, i) => {
            if (!opt.voters) opt.voters = [];
            const idx = opt.voters.indexOf(clientInfo.userId);
            if (idx !== -1) opt.voters.splice(idx, 1);
            if (i === data.optionIndex && idx === -1) opt.voters.push(clientInfo.userId);
          });
          msg.text = `[poll:${JSON.stringify(poll)}]`;
          msg.edited   = true;
          msg.editedAt = Date.now();
          DB.write();
          broadcast({ type: 'message_edited', messageId: msg.id, text: msg.text, editedAt: msg.editedAt });
        } catch {}
        break;
      }

      // ── ADMIN: KICK ──────────────────────────────────────────────
      case 'admin_kick': {
        if (!clientInfo.isOwner) return;
        if (!data.userId) return;
        // Disconnect the target user
        for (const [targetWs, info] of clients) {
          if (info.userId === data.userId) {
            try {
              targetWs.send(JSON.stringify({ type: 'kicked', message: 'You have been kicked by an admin.' }));
              setTimeout(() => { try { targetWs.close(); } catch {} }, 500);
            } catch {}
          }
        }
        DB.get();
        const kicked = db.users.find(u => u.id === data.userId);
        if (kicked) {
          pushNotification(data.userId, { type: 'kicked', emoji: '🔨', title: 'You were kicked', body: 'An admin removed you.', data: {} });
        }
        broadcast({ type: 'user_kicked', userId: data.userId });
        break;
      }

      // ── ADMIN: ANNOUNCE ──────────────────────────────────────────
      case 'admin_announce': {
        if (!clientInfo.isOwner) return;
        if (!data.text?.trim()) return;
        DB.get();
        const announcer = db.users.find(u => u.id === clientInfo.userId);
        // Send to all rooms
        db.rooms.forEach(room => {
          const announcementMsg = {
            id:        uuidv4(),
            roomId:    room.id,
            userId:    clientInfo.userId,
            text:      `📢 **[Admin Announcement]** ${data.text.trim()}`,
            replyTo:   null,
            reactions: {},
            edited:    false,
            pinned:    false,
            createdAt: Date.now(),
            isAnnouncement: true,
          };
          db.messages.push(announcementMsg);
          broadcast({ type: 'message', message: hydrateMessage(announcementMsg) });
        });
        DB.write();
        break;
      }

      // ── ADMIN: DELETE ROOM ────────────────────────────────────────
      case 'delete_room': {
        if (!clientInfo.isOwner) return;
        if (!data.roomId) return;
        if (PROTECTED_ROOMS.includes(data.roomId)) return;
        DB.get();
        db.rooms    = db.rooms.filter(r => r.id !== data.roomId);
        db.messages = db.messages.filter(m => m.roomId !== data.roomId);
        DB.write();
        broadcast({ type: 'room_deleted', roomId: data.roomId });
        break;
      }

      default:
        break;
    }
  });

  ws.on('close', () => {
    const info = clients.get(ws);
    if (info) {
      clients.delete(ws);
      const stillOnline = [...clients.values()].some(c => c.userId === info.userId);
      if (!stillOnline) {
        DB.get();
        const user = db.users.find(u => u.id === info.userId);
        if (user) {
          user.status = 'offline';
          DB.write();
        }
        broadcast({ type: 'user_offline', userId: info.userId });
      }
    }
  });

  ws.on('error', (err) => console.error('WebSocket error:', err.message));
});

// ─── Heartbeat keep-alive ──────────────────────────────────────────────────
const heartbeat = setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);
wss.on('close', () => clearInterval(heartbeat));

// ─── Periodic DB trim (every 10 minutes) ──────────────────────────────────
setInterval(() => {
  try {
    DB.get();
    // Remove very old notifications (>7 days)
    const week = 7 * 24 * 60 * 60 * 1000;
    db.notifications = db.notifications.filter(n => Date.now() - n.createdAt < week);
    // Remove rejected/removed friend requests older than 30 days
    const month = 30 * 24 * 60 * 60 * 1000;
    db.friendRequests = db.friendRequests.filter(r =>
      r.status === 'pending' || Date.now() - r.createdAt < month
    );
    DB.write();
  } catch (e) {
    console.error('Periodic trim error:', e);
  }
}, 10 * 60 * 1000);

// ─── Start server ──────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n🚀 VIBE chat server running at http://localhost:${PORT}`);
  console.log(`📁 Database: ${dbFile}`);
  console.log(`👥 Features: auth ✓ | DMs ✓ | friends ✓ | XP ✓ | shop ✓ | notifications ✓ | pins ✓ | reactions ✓ | polls ✓ | private servers ✓ | avatars ✓ | search ✓ | admin ✓`);
  if (JWT_SECRET === 'supersecretkey_changeme_in_prod_2025') {
    console.log('⚠️  Using default JWT_SECRET — set JWT_SECRET env var in production!\n');
  } else {
    console.log('🔑 JWT Secret: Custom ✓\n');
  }
});
