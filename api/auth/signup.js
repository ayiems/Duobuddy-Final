const { getUsers, saveUsers, createUserObject } = require('../_lib/store');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  try {
    const { name, email, username, password, phone } = req.body || {};
    if (!name || !email || !username || !password) { res.status(400).json({ error: 'invalid' }); return; }
    const users = await getUsers();
    if (users.find(u => u.email === email || (u.username || '').toLowerCase() === username.toLowerCase())) { res.status(409).json({ error: 'exists' }); return; }
    const now = new Date();
    const trialEnd = new Date(now); trialEnd.setDate(trialEnd.getDate() + 1);
    const user = createUserObject({ name, email, username, phone, password, is_admin: false, data: JSON.stringify({ jobTitle: '', company: '', about: '', created: now.toISOString(), trialEnd: trialEnd.toISOString(), cards: [] }) });
    users.push(user);
    await saveUsers(users);
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
};