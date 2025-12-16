const { getUsers, saveUsers, sanitizeUser } = require('../_lib/store');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  try {
    const sid = (req.headers.cookie || '').match(/sid=([^;]+)/);
    const sessions = global.__SESSIONS || new Map();
    const uid = sid ? sessions.get(sid[1]) : null;
    if (!uid) { res.status(401).json({ error: 'unauthorized' }); return; }
    const { slot, design, quantity, address, notes, paymentProof } = req.body || {};
    const users = await getUsers();
    const user = users.find(u => u.__backendId === uid);
    const profile = user.data ? JSON.parse(user.data) : {};
    const cards = profile.cards || [];
    const now = new Date().toISOString();
    const existing = cards.find(c => c.slot === slot);
    if (existing) { Object.assign(existing, { ordered: false, design, quantity, orderDate: now, paymentProof, address, notes, status: 'pending_approval' }); }
    else { cards.push({ slot, ordered: false, design, quantity, orderDate: now, paymentProof, address, notes, status: 'pending_approval' }); }
    profile.cards = cards; user.data = JSON.stringify(profile);
    await saveUsers(users);
    res.status(200).json({ user: sanitizeUser(user) });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
};