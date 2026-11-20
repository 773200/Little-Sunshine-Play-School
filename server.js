require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || './data');
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || path.join(DATA_DIR, 'uploads'));
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '7032070594';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '773200';
const ADMIN_PASSWORD_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 10);
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.warn('WARNING: Set SESSION_SECRET to a random value of at least 32 characters.');
}
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'school.sqlite'));
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS media (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL CHECK(kind IN ('photo','video')),
  filename TEXT NOT NULL,
  original_name TEXT NOT NULL,
  caption TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)`);

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(session({
  name: 'little_sunshine_admin',
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'development-only-change-this-session-secret-now',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many login attempts. Please try again in 15 minutes.' } });
const requireAdmin = (req, res, next) => req.session && req.session.admin ? next() : res.status(401).json({ error: 'Please log in to continue.' });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^.a-z0-9]/g, '').slice(0, 10);
    cb(null, `${Date.now()}-${require('crypto').randomBytes(8).toString('hex')}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 150 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const ok = /^(image\/(jpeg|png|webp|gif)|video\/(mp4|webm|quicktime))$/.test(file.mimetype);
    cb(ok ? null : new Error('Use JPG, PNG, WEBP, GIF photos or MP4, WEBM, MOV videos.'), ok);
  }
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));
app.get('/api/media', (_req, res) => {
  const rows = db.prepare('SELECT id, kind, filename, caption, description, created_at FROM media ORDER BY id DESC').all();
  res.json(rows.map(x => ({ ...x, url: `/uploads/${encodeURIComponent(x.filename)}` })));
});
app.use('/uploads', express.static(UPLOAD_DIR, { dotfiles: 'deny', index: false, maxAge: '1d' }));
app.get('/api/auth/status', (req, res) => res.json({ authenticated: !!(req.session && req.session.admin) }));
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const userOk = typeof username === 'string' && username === ADMIN_USERNAME;
  const passOk = typeof password === 'string' && await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
  if (!userOk || !passOk) return res.status(401).json({ error: 'Incorrect username or password.' });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Could not start a secure session.' });
    req.session.admin = true;
    res.json({ ok: true });
  });
});
app.post('/api/auth/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.post('/api/media', requireAdmin, (req, res) => {
  upload.single('file')(req, res, err => {
    if (err) return res.status(400).json({ error: err.message || 'Upload failed.' });
    if (!req.file) return res.status(400).json({ error: 'Choose a photo or video first.' });
    const kind = req.file.mimetype.startsWith('image/') ? 'photo' : 'video';
    const caption = String(req.body.caption || '').trim().slice(0, 140);
    const description = String(req.body.description || '').trim().slice(0, 1500);
    const info = db.prepare('INSERT INTO media (kind, filename, original_name, caption, description) VALUES (?, ?, ?, ?, ?)').run(kind, req.file.filename, req.file.originalname.slice(0, 255), caption, description);
    res.status(201).json({ id: info.lastInsertRowid, kind, filename: req.file.filename, caption, description, url: `/uploads/${encodeURIComponent(req.file.filename)}` });
  });
});
app.patch('/api/media/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid item.' });
  const caption = String(req.body.caption || '').trim().slice(0, 140);
  const description = String(req.body.description || '').trim().slice(0, 1500);
  const result = db.prepare('UPDATE media SET caption = ?, description = ? WHERE id = ?').run(caption, description, id);
  if (!result.changes) return res.status(404).json({ error: 'Item not found.' });
  res.json({ ok: true });
});
app.delete('/api/media/:id', requireAdmin, (req, res) => {
  const item = db.prepare('SELECT filename FROM media WHERE id = ?').get(Number(req.params.id));
  if (!item) return res.status(404).json({ error: 'Item not found.' });
  db.prepare('DELETE FROM media WHERE id = ?').run(Number(req.params.id));
  const target = path.join(UPLOAD_DIR, path.basename(item.filename));
  fs.promises.unlink(target).catch(() => {});
  res.json({ ok: true });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});
app.listen(PORT, () => console.log(`Little Sunshine website running on port ${PORT}`));
