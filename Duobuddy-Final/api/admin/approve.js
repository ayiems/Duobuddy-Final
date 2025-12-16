const { getUsers, saveUsers } = require('../_lib/store');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  try {
    const sid = (req.headers.cookie || '').match(/sid=([^;]+)/);
    const sessions = global.__SESSIONS || new Map();
    const uid = sid ? sessions.get(sid[1]) : null;
    const users = await getUsers();
    const admin = uid ? users.find(u => u.__backendId === uid) : null;
    if (!admin || !admin.is_admin) { res.status(403).json({ error: 'forbidden' }); return; }
    const { userId, slot, nfcSerial, nfcPassword, designImage } = req.body || {};
    const user = users.find(u => u.__backendId === userId);
    if (!user) { res.status(404).json({ error: 'user_not_found' }); return; }
    const profile = user.data ? JSON.parse(user.data) : {};
    const cards = profile.cards || [];
    let card = cards.find(c => c.slot === slot);
    const now = new Date().toISOString();
    if (!card) { card = { slot }; cards.push(card); }
    Object.assign(card, { ordered: true, status: 'active', activatedDate: now, designImage: designImage || card.designImage || null, nfcSerial: nfcSerial || '', nfcPassword: nfcPassword || '' });
    profile.cards = cards; profile.paymentApproved = true; profile.approvedDate = now;
    user.data = JSON.stringify(profile);
    await saveUsers(users);
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
};