const crypto = require('crypto');

const KV_URL = process.env.VERCEL_KV_REST_API_URL;
const KV_TOKEN = process.env.VERCEL_KV_REST_API_TOKEN;
let MEMORY = { users: [] };

async function kvGet(key){
  if(!KV_URL || !KV_TOKEN) return MEMORY[key];
  const r = await fetch(`${KV_URL}/get/${encodeURIComponent(key)}`, { headers: { Authorization: `Bearer ${KV_TOKEN}` } });
  if(!r.ok) return null;
  const d = await r.json();
  return d && d.result ? JSON.parse(d.result) : null;
}

async function kvSet(key, val){
  if(!KV_URL || !KV_TOKEN){ MEMORY[key] = val; return; }
  await fetch(`${KV_URL}/set/${encodeURIComponent(key)}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${KV_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ value: JSON.stringify(val) })
  });
}

function hashPassword(password, salt){
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
  return { salt, hash };
}

async function getUsers(){ const u = await kvGet('users'); return Array.isArray(u) ? u : []; }
async function saveUsers(users){ await kvSet('users', users); }

function createUserObject({ name, email, username, phone, password, is_admin, data }){
  const { salt, hash } = hashPassword(password);
  return { __backendId: crypto.randomBytes(8).toString('hex'), name, email, username, phone, is_admin: !!is_admin, passwordSalt: salt, passwordHash: hash, deleted: false, data: data || JSON.stringify({ created: new Date().toISOString(), cards: [] }) };
}

function sanitizeUser(u){ const { passwordHash, passwordSalt, ...safe } = u; return safe; }

function setCookie(res, name, value, opts){
  const parts = [`${name}=${value}`];
  if(opts?.httpOnly !== false) parts.push('HttpOnly');
  parts.push('Path=/');
  if(opts?.maxAge) parts.push(`Max-Age=${opts.maxAge}`);
  parts.push('SameSite=Lax');
  if(opts?.secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function getCookie(req, name){ const h = req.headers.cookie || ''; const m = h.match(new RegExp(`${name}=([^;]+)`)); return m ? m[1] : null; }

module.exports = { getUsers, saveUsers, createUserObject, sanitizeUser, hashPassword, setCookie, getCookie };