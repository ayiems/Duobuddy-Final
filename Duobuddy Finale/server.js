const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = 5000;
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS = new Map();
const ORIGIN = 'http://localhost:8000';

function ensureData() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
  if (!fs.existsSync(USERS_FILE)) {
    const admin = createUserObject({
      name: 'Administrator',
      email: 'admin@admin',
      username: 'systemadmin',
      phone: '+60 12-000 0000',
      password: 'admin',
      is_admin: true,
      data: JSON.stringify({ jobTitle: 'Administrator', company: 'DuoBuddy', about: 'System Administrator', created: new Date().toISOString() })
    });
    fs.writeFileSync(USERS_FILE, JSON.stringify([admin], null, 2));
  }
}

function readUsers() {
  ensureData();
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { return []; }
}

function writeUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
  return { salt, hash };
}

function createUserObject({ name, email, username, phone, password, is_admin, data }) {
  const { salt, hash } = hashPassword(password);
  return {
    __backendId: crypto.randomBytes(8).toString('hex'),
    name,
    email,
    username,
    phone,
    is_admin: !!is_admin,
    passwordSalt: salt,
    passwordHash: hash,
    deleted: false,
    data: data || JSON.stringify({ created: new Date().toISOString(), cards: [] })
  };
}

function sanitizeUser(u) {
  const { passwordHash, passwordSalt, ...safe } = u;
  return safe;
}

function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', ORIGIN);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function setJson(res) { res.setHeader('Content-Type', 'application/json'); }

function parseBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); } catch (e) { resolve({}); }
    });
  });
}

function setCookie(res, name, value, opts = {}) {
  const parts = [`${name}=${value}`];
  if (opts.httpOnly !== false) parts.push('HttpOnly');
  parts.push('Path=/');
  if (opts.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`); else parts.push('SameSite=Lax');
  if (opts.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function getCookie(req, name) {
  const header = req.headers['cookie'];
  if (!header) return null;
  const cookies = Object.fromEntries(header.split(';').map(s => s.trim().split('=')));
  return cookies[name] || null;
}

const server = http.createServer(async (req, res) => {
  setCors(res);
  if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }
  const parsed = url.parse(req.url, true);
  const pathName = parsed.pathname || '';

  // Auth: signup
  if (req.method === 'POST' && pathName === '/api/auth/signup') {
    const body = await parseBody(req);
    const { name, email, username, password, phone } = body;
    if (!name || !email || !username || !password) { setJson(res); res.writeHead(400).end(JSON.stringify({ error: 'invalid' })); return; }
    const users = readUsers();
    if (users.find(u => u.email === email || u.username === username)) { setJson(res); res.writeHead(409).end(JSON.stringify({ error: 'exists' })); return; }
    const now = new Date();
    const trialEnd = new Date(now); trialEnd.setDate(trialEnd.getDate() + 1);
    const user = createUserObject({ name, email, username, phone, password, is_admin: false, data: JSON.stringify({ jobTitle: '', company: '', about: '', created: now.toISOString(), trialEnd: trialEnd.toISOString(), cards: [] }) });
    users.push(user);
    writeUsers(users);
    setJson(res);
    res.writeHead(200).end(JSON.stringify({ ok: true }));
    return;
  }

  // Auth: login
  if (req.method === 'POST' && pathName === '/api/auth/login') {
    const body = await parseBody(req);
    const { email, password } = body;
    const users = readUsers();
    const user = users.find(u => u.email === email);
    if (!user) { setJson(res); res.writeHead(401).end(JSON.stringify({ error: 'invalid' })); return; }
    const { hash } = hashPassword(password, user.passwordSalt);
    if (hash !== user.passwordHash) { setJson(res); res.writeHead(401).end(JSON.stringify({ error: 'invalid' })); return; }
    const sid = crypto.randomBytes(16).toString('hex');
    SESSIONS.set(sid, user.__backendId);
    setCookie(res, 'sid', sid, { httpOnly: true });
    setJson(res);
    res.writeHead(200).end(JSON.stringify({ user: sanitizeUser(user) }));
    return;
  }

  // Auth: logout
  if (req.method === 'POST' && pathName === '/api/auth/logout') {
    const sid = getCookie(req, 'sid');
    if (sid) SESSIONS.delete(sid);
    setCookie(res, 'sid', '', { httpOnly: true, maxAge: 0 });
    setJson(res);
    res.writeHead(200).end(JSON.stringify({ ok: true }));
    return;
  }

  // Current user
  if (req.method === 'GET' && pathName === '/api/users/me') {
    const sid = getCookie(req, 'sid');
    const users = readUsers();
    const uid = sid ? SESSIONS.get(sid) : null;
    const user = uid ? users.find(u => u.__backendId === uid) : null;
    setJson(res);
    res.writeHead(200).end(JSON.stringify({ user: user ? sanitizeUser(user) : null }));
    return;
  }

  // Public profile by username
  if (req.method === 'GET' && pathName.startsWith('/api/profile/')) {
    const username = decodeURIComponent(pathName.replace('/api/profile/', ''));
    const users = readUsers();
    const user = users.find(u => u.username && u.username.toLowerCase() === username.toLowerCase());
    if (!user || user.deleted) { setJson(res); res.writeHead(404).end(JSON.stringify({ error: 'not_found' })); return; }
    setJson(res);
    res.writeHead(200).end(JSON.stringify({ user: sanitizeUser(user) }));
    return;
  }

  // Place card order (auth required)
  if (req.method === 'POST' && pathName === '/api/cards/order') {
    const sid = getCookie(req, 'sid');
    const uid = sid ? SESSIONS.get(sid) : null;
    if (!uid) { setJson(res); res.writeHead(401).end(JSON.stringify({ error: 'unauthorized' })); return; }
    const body = await parseBody(req);
    const { slot, design, quantity, address, notes, paymentProof } = body;
    const users = readUsers();
    const user = users.find(u => u.__backendId === uid);
    const profileData = user.data ? JSON.parse(user.data) : {};
    const cards = profileData.cards || [];
    const existing = cards.find(c => c.slot === slot);
    const nowIso = new Date().toISOString();
    if (existing) {
      existing.ordered = false;
      existing.design = design;
      existing.quantity = quantity;
      existing.orderDate = nowIso;
      existing.paymentProof = paymentProof;
      existing.address = address;
      existing.notes = notes;
      existing.status = 'pending_approval';
    } else {
      cards.push({ slot, ordered: false, design, quantity, orderDate: nowIso, paymentProof, address, notes, status: 'pending_approval' });
    }
    profileData.cards = cards;
    user.data = JSON.stringify(profileData);
    writeUsers(users);
    setJson(res);
    res.writeHead(200).end(JSON.stringify({ user: sanitizeUser(user) }));
    return;
  }

  // Admin: approve payment (auth + admin)
  if (req.method === 'POST' && pathName === '/api/admin/approve') {
    const sid = getCookie(req, 'sid');
    const uid = sid ? SESSIONS.get(sid) : null;
    const users = readUsers();
    const admin = uid ? users.find(u => u.__backendId === uid) : null;
    if (!admin || !admin.is_admin) { setJson(res); res.writeHead(403).end(JSON.stringify({ error: 'forbidden' })); return; }
    const body = await parseBody(req);
    const { userId, slot, nfcSerial, nfcPassword, designImage } = body;
    const user = users.find(u => u.__backendId === userId);
    if (!user) { setJson(res); res.writeHead(404).end(JSON.stringify({ error: 'user_not_found' })); return; }
    const profileData = user.data ? JSON.parse(user.data) : {};
    const cards = profileData.cards || [];
    let card = cards.find(c => c.slot === slot);
    const nowIso = new Date().toISOString();
    if (!card) { card = { slot }; cards.push(card); }
    card.ordered = true;
    card.status = 'active';
    card.activatedDate = nowIso;
    card.designImage = designImage || card.designImage || null;
    card.nfcSerial = nfcSerial || '';
    card.nfcPassword = nfcPassword || '';
    profileData.cards = cards;
    profileData.paymentApproved = true;
    profileData.approvedDate = nowIso;
    user.data = JSON.stringify(profileData);
    writeUsers(users);
    setJson(res);
    res.writeHead(200).end(JSON.stringify({ user: sanitizeUser(user) }));
    return;
  }

  setJson(res);
  res.writeHead(404).end(JSON.stringify({ error: 'not_found' }));
});

server.listen(PORT, () => {
  console.log(`API server running on http://localhost:${PORT}`);
});