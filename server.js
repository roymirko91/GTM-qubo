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
    pool.query(`
      CREATE TABLE IF NOT EXISTS dashboard_data (
        id      INTEGER PRIMARY KEY DEFAULT 1,
        data    JSONB NOT NULL DEFAULT '{}',
        updated_at TIMESTAMPTZ DEFAULT NOW(),
        CONSTRAINT single_row CHECK (id = 1)
      );
      CREATE TABLE IF NOT EXISTS user_passwords (
        username     TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt         TEXT NOT NULL,
        must_change  BOOLEAN DEFAULT TRUE,
        updated_at   TIMESTAMPTZ DEFAULT NOW()
      );
    `).then(() => {
      console.log('DB lista');
    }).catch(e => console.error('DB init error:', e.message));
  }
  return pool;
}

// ─── Helpers de password ──────────────────────────────────────────────────────
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
function makeHash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return { salt, hash: hashPassword(password, salt) };
}
function verifyHash(password, salt, hash) {
  return hashPassword(password, salt) === hash;
}

// Verificar contraseña contra DB primero, luego contra config.
// Devuelve { user, must_change } o null si credenciales incorrectas.
async function verifyLogin(username, password) {
  const users = loadUsers();
  const cfgUser = users.find(u =>
    u.username.toLowerCase().trim() === username.toLowerCase().trim()
  );
  if (!cfgUser) return null;

  const p = getPool();
  if (p) {
    try {
      const r = await p.query('SELECT * FROM user_passwords WHERE username = $1', [cfgUser.username]);
      if (r.rows.length > 0) {
        const row = r.rows[0];
        if (!verifyHash(password, row.salt, row.password_hash)) return null;
        return { user: cfgUser, must_change: row.must_change };
      }
    } catch (e) {
      console.error('verifyLogin DB error:', e.message);
    }
  }
  // No hay registro en DB: verificar contra contraseña de config
  if (cfgUser.password !== password) return null;
  // Primer login: guardar hash en DB y marcar must_change=true
  if (p) {
    try {
      const { salt, hash } = makeHash(password);
      await p.query(`
        INSERT INTO user_passwords (username, password_hash, salt, must_change)
        VALUES ($1, $2, $3, TRUE)
        ON CONFLICT (username) DO NOTHING
      `, [cfgUser.username, hash, salt]);
    } catch (e) {
      console.error('First login hash save error:', e.message);
    }
  }
  return { user: cfgUser, must_change: true };
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
    { username: 'roy.mirko@it4w.net',     password: '1234', name: 'Roy',    role: 'super_admin' },
    { username: 'ehitgaby.pena@it4w.net', password: '456',  name: 'Ehitga', role: 'editor'      },
    { username: 'santiago.fain@it4w.net', password: '987',  name: 'Santi',  role: 'editor'      }
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
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
  }
  const result = await verifyLogin(username.trim(), password);
  if (!result) {
    addLog({ type: 'login_failed', username: username.trim(), ip: req.ip });
    return res.status(401).json({ error: 'Credenciales incorrectas.' });
  }
  const { user, must_change } = result;
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, name: user.name, role: user.role });
  addLog({ type: 'login', username: user.username, name: user.name, ip: req.ip });
  res.json({ token, name: user.name, role: user.role, username: user.username, must_change });
});

// POST /api/change-password
app.post('/api/change-password', requireAuth, async (req, res) => {
  const { current_password, new_password } = req.body || {};
  if (!current_password || !new_password) {
    return res.status(400).json({ error: 'Faltan campos.' });
  }
  if (new_password.length < 8) {
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres.' });
  }
  // Verificar contraseña actual
  const check = await verifyLogin(req.session.username, current_password);
  if (!check) {
    return res.status(401).json({ error: 'Contraseña actual incorrecta.' });
  }
  const p = getPool();
  if (!p) return res.status(503).json({ error: 'Base de datos no disponible.' });
  try {
    const { salt, hash } = makeHash(new_password);
    await p.query(`
      INSERT INTO user_passwords (username, password_hash, salt, must_change)
      VALUES ($1, $2, $3, FALSE)
      ON CONFLICT (username) DO UPDATE
        SET password_hash = $2, salt = $3, must_change = FALSE, updated_at = NOW()
    `, [req.session.username, hash, salt]);
    addLog({ type: 'activity', username: req.session.username, name: req.session.name, action: 'change_password', detail: '' });
    res.json({ ok: true });
  } catch (e) {
    console.error('change-password error:', e.message);
    res.status(500).json({ error: 'Error al guardar contraseña.' });
  }
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
  if (req.session.role !== 'super_admin' && req.session.role !== 'admin') {
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
