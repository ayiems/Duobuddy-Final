const { setCookie } = require('../_lib/store');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  try {
    const sid = (req.headers.cookie || '').match(/sid=([^;]+)/);
    if (sid && global.__SESSIONS) global.__SESSIONS.delete(sid[1]);
    setCookie(res, 'sid', '', { maxAge: 0 });
    res.status(200).json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
};