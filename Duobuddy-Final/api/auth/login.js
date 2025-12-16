const { getUsers, saveUsers, createUserObject, sanitizeUser, hashPassword, setCookie } = require('../_lib/store');

module.exports = async (req, res) => {
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'method_not_allowed' }); return; }
  try {
    const { email, password } = req.body || {};
    let users = await getUsers();
    const adminEmail = 'admin@duobuddy.my';
    const hasNewAdmin = users.some(u => u.is_admin && u.email === adminEmail);
    const pruned = users.filter(u => !(u.is_admin && u.email !== adminEmail));
    let changed = pruned.length !== users.length;
    users = pruned;
    if (!hasNewAdmin) {
      users.push(createUserObject({
        name: 'Administrator',
        email: adminEmail,
        username: 'systemadmin',
        phone: '+60 12-000 0000',
        password: 'Admin@123!',
        is_admin: true,
        data: JSON.stringify({ jobTitle: 'Administrator', company: 'DuoBuddy', about: 'System Administrator', created: new Date().toISOString() })
      }));
      changed = true;
    }
    if (changed) await saveUsers(users);
    const user = users.find(u => u.email === email);
    if (!user) { res.status(401).json({ error: 'invalid' }); return; }
    const { hash } = hashPassword(password, user.passwordSalt);
    if (hash !== user.passwordHash) { res.status(401).json({ error: 'invalid' }); return; }
    const sid = Math.random().toString(36).slice(2);
    global.__SESSIONS = global.__SESSIONS || new Map();
    global.__SESSIONS.set(sid, user.__backendId);
    setCookie(res, 'sid', sid, {});
    res.status(200).json({ user: sanitizeUser(user) });
  } catch (e) {
    res.status(500).json({ error: 'server_error' });
  }
};
