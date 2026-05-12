const express = require('express');
const path    = require('path');
const crypto  = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

// ─── Base de datos (Render PostgreSQL) ───────────────────────────────────────
let pool = null;

function getPool() {
  if (!pool && process.env.DATABASE_URL) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });
    // Crear tabla si no existe
    pool.query(`
      CREATE TABLE IF NOT EXISTS dashboard_data (
        id      INTEGER PRIMARY KEY DEFAULT 1,
        data    JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        CONSTRAINT single_row CHECK (id = 1)
      )
    `).then(() => {
      console.log('DB lista');
    }).catch(e => console.error('DB init error:', e.message));
  }
  return pool;
}

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
    { username: 'roy.mirko@it4w.net', password: '1234', name: 'Roy',    role: 'super_admin' },
    { username: 'ehitga',             password: '456',  name: 'Ehitga', role: 'editor'      },
    { username: 'santi',              password: '987',  name: 'Santi',  role: 'editor'      }
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
  if (req.session.role !== 'super_admin') {
    return res.status(403).json({ error: 'Acceso denegado. Solo super administradores.' });
  }
  // Devolver más recientes primero
  res.json([...activityLog].reverse());
});

// GET /api/health
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', sessions: sessions.size, logs: activityLog.length, db: !!getPool() });
});

// GET / → sirve el dashboard
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'qubo-gtm-dashboard.html'));
});

// ─── Persistencia del estado del dashboard ────────────────────────────────────

// GET /api/store → devuelve el estado completo del dashboard
app.get('/api/store', requireAuth, async (req, res) => {
  const p = getPool();
  if (!p) return res.json({});
  try {
    const result = await p.query('SELECT data FROM dashboard_data WHERE id = 1');
    res.json(result.rows[0]?.data || {});
  } catch (e) {
    console.error('Store GET error:', e.message);
    res.json({});
  }
});

// POST /api/store → guarda el estado completo del dashboard
app.post('/api/store', requireAuth, async (req, res) => {
  const p = getPool();
  if (!p) return res.json({ ok: true, persisted: false });
  const data = req.body || {};
  try {
    await p.query(`
      INSERT INTO dashboard_data (id, data, updated_at)
      VALUES (1, $1::jsonb, NOW())
      ON CONFLICT (id) DO UPDATE SET data = $1::jsonb, updated_at = NOW()
    `, [JSON.stringify(data)]);
    addLog({ type: 'activity', username: req.session.username, name: req.session.name, action: 'autosave', detail: '' });
    res.json({ ok: true, persisted: true });
  } catch (e) {
    console.error('Store POST error:', e.message);
    res.status(500).json({ error: 'Error guardando datos: ' + e.message });
  }
});

// ─── Arranque ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GTM qubo Dashboard escuchando en puerto ${PORT}`);
});
