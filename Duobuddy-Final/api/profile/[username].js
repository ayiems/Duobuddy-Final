const { getUsers, sanitizeUser } = require('../_lib/store');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'GET') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  try {
    const { username } = req.query;
    const users = await getUsers();
    const user = users.find(u => (u.username || '').toLowerCase() === String(username).toLowerCase());
    if (!user || user.deleted) { res.status(404).json({ error: 'not_found' }); return; }
    res.status(200).json({ user: sanitizeUser(user) });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
};