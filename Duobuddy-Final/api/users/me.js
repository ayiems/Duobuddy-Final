const { getUsers, sanitizeUser } = require('../_lib/store');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'GET') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  try {
    const sid = (req.headers.cookie || '').match(/sid=([^;]+)/);
    const sessions = global.__SESSIONS || new Map();
    const uid = sid ? sessions.get(sid[1]) : null;
    const users = await getUsers();
    const user = uid ? users.find(u => u.__backendId === uid) : null;
    res.status(200).json({ user: user ? sanitizeUser(user) : null });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
};