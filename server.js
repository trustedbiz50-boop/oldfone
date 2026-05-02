require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const QRCode = require('qrcode');
const cron = require('node-cron');
const path = require('path');
const { makeWASocket, useMultiFileAuthState, DisconnectReason, fetchLatestBaileysVersion } = require('@whiskeysockets/baileys');
const pino = require('pino');

const app = express();
const PORT = process.env.PORT || 3000;

// ── DATABASE ──────────────────────────────────────────────────────────────────
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      phone TEXT,
      plan TEXT DEFAULT 'free',         -- 'free' | 'pro'
      plan_expires_at TIMESTAMPTZ,       -- NULL = never (pro)
      momo_name TEXT,
      momo_ref TEXT,
      status TEXT DEFAULT 'pending',     -- 'pending' | 'active' | 'suspended'
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS wa_sessions (
      user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      session_data TEXT,                 -- JSON stringified Baileys creds
      wa_number TEXT,
      connected BOOLEAN DEFAULT FALSE,
      last_seen TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS payments (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID REFERENCES users(id),
      amount INTEGER NOT NULL,           -- UGX
      momo_number TEXT NOT NULL,
      momo_name TEXT,
      network TEXT NOT NULL,             -- 'mtn' | 'airtel'
      plan TEXT NOT NULL,
      ref TEXT,
      status TEXT DEFAULT 'pending',     -- 'pending' | 'confirmed' | 'rejected'
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('✅ Database ready');
}

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'oldfone-secret-uganda-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in' });
  next();
}
function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ── ACTIVE WA SOCKETS (in-memory) ────────────────────────────────────────────
const activeSockets = {}; // userId -> { sock, qr, status }

async function startWASession(userId, savedCreds) {
  const logger = pino({ level: 'silent' });
  const { version } = await fetchLatestBaileysVersion();

  // Build auth state from saved DB creds or fresh
  let state, saveCreds;
  if (savedCreds) {
    const parsed = JSON.parse(savedCreds);
    state = { creds: parsed.creds, keys: parsed.keys || {} };
    saveCreds = async () => {
      const updated = JSON.stringify({ creds: state.creds, keys: state.keys });
      await db.query('UPDATE wa_sessions SET session_data=$1, last_seen=NOW() WHERE user_id=$2', [updated, userId]);
    };
  } else {
    // Use temp in-memory state for fresh sessions
    const { state: s, saveCreds: sc } = await useMultiFileAuthState(`/tmp/wa_${userId}`);
    state = s; saveCreds = sc;
  }

  const sock = makeWASocket({ version, auth: state, logger, printQRInTerminal: false, browser: ['OldFone', 'Chrome', '1.0'] });
  activeSockets[userId] = { sock, qr: null, status: 'connecting' };

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async (update) => {
    const { connection, lastDisconnect, qr } = update;

    if (qr) {
      const qrImage = await QRCode.toDataURL(qr);
      activeSockets[userId] = { ...activeSockets[userId], qr: qrImage, status: 'awaiting_scan' };
    }

    if (connection === 'open') {
      const waNumber = sock.user?.id?.split(':')[0] || '';
      activeSockets[userId] = { ...activeSockets[userId], status: 'connected', qr: null };
      // Persist session
      const credsJson = JSON.stringify({ creds: state.creds, keys: state.keys || {} });
      await db.query(`
        INSERT INTO wa_sessions (user_id, session_data, wa_number, connected)
        VALUES ($1,$2,$3,true)
        ON CONFLICT (user_id) DO UPDATE SET session_data=$2, wa_number=$3, connected=true, last_seen=NOW()
      `, [userId, credsJson, waNumber]);
      console.log(`✅ WA connected for user ${userId}`);
    }

    if (connection === 'close') {
      const reason = lastDisconnect?.error?.output?.statusCode;
      activeSockets[userId] = { ...activeSockets[userId], status: 'disconnected' };
      await db.query('UPDATE wa_sessions SET connected=false WHERE user_id=$1', [userId]);
      // Reconnect unless logged out
      if (reason !== DisconnectReason.loggedOut) {
        console.log(`🔄 Reconnecting user ${userId}...`);
        setTimeout(() => startWASession(userId, null), 5000);
      }
    }
  });

  return sock;
}

// ── AUTH ROUTES ───────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6)
    return res.json({ ok: false, error: 'Email and password (6+ chars) required' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const result = await db.query(
      'INSERT INTO users (email, password_hash) VALUES ($1,$2) RETURNING id, email, plan, status',
      [email.toLowerCase().trim(), hash]
    );
    const user = result.rows[0];
    req.session.userId = user.id;
    req.session.role = 'user';
    res.json({ ok: true, user: { email: user.email, plan: user.plan, status: user.status } });
  } catch (e) {
    if (e.code === '23505') return res.json({ ok: false, error: 'Email already registered' });
    res.json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    const user = result.rows[0];
    if (!user) return res.json({ ok: false, error: 'Email not found' });
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.json({ ok: false, error: 'Wrong password' });

    req.session.userId = user.id;
    req.session.role = user.email === process.env.ADMIN_EMAIL ? 'admin' : 'user';
    res.json({ ok: true, user: { email: user.email, plan: user.plan, status: user.status }, isAdmin: req.session.role === 'admin' });
  } catch (e) {
    res.json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const r = await db.query('SELECT id, email, plan, status, phone FROM users WHERE id=$1', [req.session.userId]);
  const u = r.rows[0];
  if (!u) return res.json({ ok: false });
  const ws = await db.query('SELECT wa_number, connected FROM wa_sessions WHERE user_id=$1', [u.id]);
  const socket = activeSockets[u.id];
  res.json({ ok: true, user: u, wa: ws.rows[0] || null, socketStatus: socket?.status || 'none' });
});

// ── WHATSAPP ROUTES ───────────────────────────────────────────────────────────
app.post('/api/wa/start', requireAuth, async (req, res) => {
  const userId = req.session.userId;

  // Check account active
  const ur = await db.query('SELECT status, plan FROM users WHERE id=$1', [userId]);
  const user = ur.rows[0];
  if (user.status !== 'active') return res.json({ ok: false, error: 'Account not active. Please pay to activate.' });

  // Load saved session if exists
  const sr = await db.query('SELECT session_data FROM wa_sessions WHERE user_id=$1', [userId]);
  const savedCreds = sr.rows[0]?.session_data || null;

  if (activeSockets[userId]?.status === 'connected') return res.json({ ok: true, status: 'already_connected' });

  await startWASession(userId, savedCreds);
  res.json({ ok: true, status: 'starting' });
});

app.get('/api/wa/qr', requireAuth, async (req, res) => {
  const socket = activeSockets[req.session.userId];
  if (!socket) return res.json({ ok: false, status: 'not_started' });
  res.json({ ok: true, status: socket.status, qr: socket.qr || null });
});

app.get('/api/wa/status', requireAuth, async (req, res) => {
  const socket = activeSockets[req.session.userId];
  res.json({ ok: true, status: socket?.status || 'none' });
});

app.get('/api/wa/chats', requireAuth, async (req, res) => {
  const socket = activeSockets[req.session.userId];
  if (!socket || socket.status !== 'connected') return res.json({ ok: false, error: 'Not connected' });
  try {
    const chats = await socket.sock.groupFetchAllParticipating();
    // Return basic chat list — in production you'd store chat history in DB
    res.json({ ok: true, chats: Object.values(chats).slice(0, 20) });
  } catch {
    res.json({ ok: true, chats: [] });
  }
});

app.post('/api/wa/send', requireAuth, async (req, res) => {
  const { to, message } = req.body;
  const socket = activeSockets[req.session.userId];
  if (!socket || socket.status !== 'connected') return res.json({ ok: false, error: 'Not connected' });
  try {
    const jid = to.includes('@') ? to : `${to}@s.whatsapp.net`;
    await socket.sock.sendMessage(jid, { text: message });
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

// ── PAYMENT ROUTES ────────────────────────────────────────────────────────────
// User submits payment proof (manual MoMo/Airtel)
app.post('/api/payment/submit', requireAuth, async (req, res) => {
  const { momo_number, momo_name, network, plan, ref } = req.body;
  const amount = plan === 'pro' ? 7000 : 25000; // UGX 7k/mo or 25k/3mo
  try {
    await db.query(
      'INSERT INTO payments (user_id, amount, momo_number, momo_name, network, plan, ref) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [req.session.userId, amount, momo_number, momo_name, network, plan, ref]
    );
    res.json({ ok: true, message: 'Payment submitted. We will activate your account within 1 hour.' });
  } catch (e) {
    res.json({ ok: false, error: 'Error saving payment' });
  }
});

app.get('/api/payment/status', requireAuth, async (req, res) => {
  const r = await db.query(
    'SELECT status, plan, created_at FROM payments WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1',
    [req.session.userId]
  );
  res.json({ ok: true, payment: r.rows[0] || null });
});

// ── ADMIN ROUTES ──────────────────────────────────────────────────────────────
app.get('/api/admin/payments', requireAdmin, async (req, res) => {
  const r = await db.query(`
    SELECT p.*, u.email FROM payments p
    JOIN users u ON u.id = p.user_id
    WHERE p.status = 'pending'
    ORDER BY p.created_at ASC
  `);
  res.json({ ok: true, payments: r.rows });
});

app.post('/api/admin/confirm-payment', requireAdmin, async (req, res) => {
  const { payment_id, user_id, plan } = req.body;
  const expiresAt = plan === 'pro' ? null : new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  try {
    await db.query('UPDATE payments SET status=$1 WHERE id=$2', ['confirmed', payment_id]);
    await db.query(
      'UPDATE users SET status=$1, plan=$2, plan_expires_at=$3 WHERE id=$4',
      ['active', plan, expiresAt, user_id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: false, error: e.message });
  }
});

app.post('/api/admin/reject-payment', requireAdmin, async (req, res) => {
  const { payment_id } = req.body;
  await db.query('UPDATE payments SET status=$1 WHERE id=$2', ['rejected', payment_id]);
  res.json({ ok: true });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const r = await db.query('SELECT id, email, plan, status, phone, created_at FROM users ORDER BY created_at DESC LIMIT 100');
  res.json({ ok: true, users: r.rows });
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  const [users, active, payments, revenue] = await Promise.all([
    db.query('SELECT COUNT(*) FROM users'),
    db.query("SELECT COUNT(*) FROM users WHERE status='active'"),
    db.query("SELECT COUNT(*) FROM payments WHERE status='confirmed'"),
    db.query("SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='confirmed'")
  ]);
  res.json({
    ok: true,
    stats: {
      totalUsers: users.rows[0].count,
      activeUsers: active.rows[0].count,
      confirmedPayments: payments.rows[0].count,
      revenueUGX: revenue.rows[0].total
    }
  });
});

// ── CRON: expire free plans ───────────────────────────────────────────────────
cron.schedule('0 * * * *', async () => {
  await db.query(`
    UPDATE users SET status='suspended', plan='free'
    WHERE plan='free' AND plan_expires_at IS NOT NULL AND plan_expires_at < NOW()
  `);
  console.log('⏰ Checked plan expirations');
});

// ── SERVE PAGES ───────────────────────────────────────────────────────────────
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});
app.get('/admin', (req, res) => {
  if (req.session.role !== 'admin') return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── START ─────────────────────────────────────────────────────────────────────
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 OldFone running on port ${PORT}`));
});
