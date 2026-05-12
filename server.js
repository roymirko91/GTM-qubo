const express = require('express');
const path    = require('path');
const crypto  = require('crypto');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// ─── Usuarios ────────────────────────────────────────────────────────────────
// Para producción en Render: setear la variable de entorno USERS_CONFIG como
// JSON array. Ejemplo:
// [{"username":"roy@it4w.com","password":"SuperPass1!","name":"Roy","role":"admin"}]
function loadUsers() {
  if (process.env.USERS_CONFIG) {
    try { return JSON.parse(process.env.USERS_CONFIG); }
    catch (e) { console.error('USERS_CONFIG inválido:', e.message); }
  }
  // Usuarios por defecto (solo para desarrollo local)
  return [
    { username: 'roy',    password: '1234', name: 'Roy',    role: 'admin' },
    { username: 'ehitga', password: '456',  name: 'Ehitga', role: 'user'  },
    { username: 'santi',  password: '987',  name: 'Santi',  role: 'user'  }
  ];
}

// ─── Sesiones y logs (en memoria) ────────────────────────────────────────────
// Nota: se resetean cuando Render reinicia el servidor (free tier).
// Para persistencia real, agregar una base de datos (PlanetScale, Supabase, etc.)
const sessions    = new Map(); // token → { username, name, role }
const activityLog = [];        // array de eventos

function addLog(entry) {
  activityLog.push({ ...entry, timestamp: new Date().toISOString() });
}

// ─── Middleware de autenticación ──────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Sesión inválida o expirada. Volvé a iniciar sesión.' });
  }
  req.session = sessions.get(token);
  next();
}

// ─── Rutas de API ─────────────────────────────────────────────────────────────

// POST /api/login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
  }

  const users = loadUsers();
  const user  = users.find(u =>
    u.username.toLowerCase().trim() === username.toLowerCase().trim() &&
    u.password === password
  );

  if (!user) {
    addLog({ type: 'login_failed', username: username.trim(), ip: req.ip });
    return res.status(401).json({ error: 'Credenciales incorrectas.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, name: user.name, role: user.role });

  addLog({ type: 'login', username: user.username, name: user.name, ip: req.ip });

  res.json({ token, name: user.name, role: user.role, username: user.username });
});

// POST /api/logout
app.post('/api/logout', requireAuth, (req, res) => {
  addLog({ type: 'logout', username: req.session.username, name: req.session.name });
  sessions.delete(req.headers['x-auth-token']);
  res.json({ ok: true });
});

// GET /api/me  — verificar sesión activa
app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.session);
});

// POST /api/activity  — registrar acción del usuario
app.post('/api/activity', requireAuth, (req, res) => {
  const { action, detail } = req.body || {};
  addLog({
    type:     'activity',
    username: req.session.username,
    name:     req.session.name,
    action:   action || '',
    detail:   detail || ''
  });
  res.json({ ok: true });
});

// GET /api/logs  — solo admin
app.get('/api/logs', requireAuth, (req, res) => {
  if (req.session.role !== 'admin') {
    return res.status(403).json({ error: 'Acceso denegado. Solo administradores.' });
  }
  // Devolver más recientes primero
  res.json([...activityLog].reverse());
});

// GET /api/health
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', sessions: sessions.size, logs: activityLog.length });
});

// ─── Arranque ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GTM qubo Dashboard escuchando en puerto ${PORT}`);
});
