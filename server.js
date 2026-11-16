require('dotenv').config();
const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
const http = require('http');
const nodemailer = require('nodemailer');
const { Server } = require('socket.io');

const app = express();
const PORT = process.env.PORT || 3000;
const rootDir = __dirname;
const dataDir = process.env.DATA_DIR || path.join(rootDir, 'data');
const dbPath = path.join(dataDir, 'avara.db');
const avatarsDir = path.join(dataDir, 'avatars');
const uploadsDir = path.join(dataDir, 'uploads');

fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(avatarsDir, { recursive: true });
fs.mkdirSync(uploadsDir, { recursive: true });
const backupsDir = path.join(dataDir, 'backups');
fs.mkdirSync(backupsDir, { recursive: true });

// ---- Email (SMTP optional — falls back to console logging) ----
const mailTransport = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: process.env.SMTP_SECURE === 'true',
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
    })
  : null;

const MAIL_FROM = process.env.MAIL_FROM || 'Avara <noreply@avara.is>';

async function sendMail({ to, subject, text, html, replyTo }) {
  if (!mailTransport) {
    console.error('[MAIL] SMTP is not configured; email was not sent.');
    return false;
  }
  try {
    await mailTransport.sendMail({ from: MAIL_FROM, to, subject, text, html, replyTo });
    return true;
  } catch (error) {
    console.error('MAIL ERROR:', error.message);
    return false;
  }
}

// ---- TOTP (RFC 6238) — dependency-free two-factor codes ----
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of clean) {
    value = (value << 5) | BASE32_ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function hotp(secretBuffer, counter) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', secretBuffer).update(buf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(code % 1000000).padStart(6, '0');
}

function verifyTotp(secretBase32, code, windowSteps = 1) {
  const normalized = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  const secretBuffer = base32Decode(secretBase32);
  if (!secretBuffer.length) return false;
  const current = Math.floor(Date.now() / 30000);
  for (let i = -windowSteps; i <= windowSteps; i++) {
    if (hotp(secretBuffer, current + i) === normalized) return true;
  }
  return false;
}

// ---- Minimal cookie parsing (session-authenticated sockets) ----
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((part) => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    try { out[key] = decodeURIComponent(val); } catch (e) { out[key] = val; }
  });
  return out;
}

function getSessionIdFromCookie(raw) {
  if (!raw) return null;
  let val = raw;
  try { val = decodeURIComponent(raw); } catch (e) { /* keep raw */ }
  if (val.startsWith('s:')) val = val.slice(2);
  const dot = val.lastIndexOf('.');
  if (dot > -1) val = val.slice(0, dot);
  return val || null;
}

// ---- CSV helpers (exports) ----
function csvEscape(value) {
  const str = value === null || value === undefined ? '' : String(value);
  if (/[",\n\r]/.test(str)) return '"' + str.replace(/"/g, '""') + '"';
  return str;
}

function toCsv(rows, columns) {
  const header = columns.map((c) => csvEscape(c.label || c.key)).join(',');
  const lines = rows.map((row) => columns.map((c) => csvEscape(typeof c.format === 'function' ? c.format(row) : row[c.key])).join(','));
  return [header, ...lines].join('\r\n');
}

// ---- Date helpers ----
function businessDaysBetween(startStr, endStr) {
  const start = new Date(startStr);
  const end = new Date(endStr);
  if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end < start) return 0;
  let count = 0;
  const cursor = new Date(start);
  while (cursor <= end) {
    const day = cursor.getDay();
    if (day !== 0 && day !== 6) count++;
    cursor.setDate(cursor.getDate() + 1);
  }
  return count;
}

function isoDate(date) {
  return date.toISOString().slice(0, 10);
}

const ALLOWED_IMAGE_TYPES = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/webp': '.webp',
  'image/gif': '.gif'
};

const ALLOWED_FILE_TYPES = {
  'image/png': '.png',
  'image/jpeg': '.jpg',
  'image/webp': '.webp',
  'image/gif': '.gif',
  'application/pdf': '.pdf',
  'text/plain': '.txt',
  'application/msword': '.doc',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': '.docx',
  'application/vnd.ms-excel': '.xls',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': '.xlsx',
  'application/zip': '.zip',
  'application/json': '.json',
  'text/csv': '.csv'
};

const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, avatarsDir),
    filename: (req, file, cb) => {
      const ext = ALLOWED_IMAGE_TYPES[file.mimetype] || '.jpg';
      cb(null, `${req.session.user.id}-${crypto.randomBytes(8).toString('hex')}${ext}`);
    }
  }),
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_IMAGE_TYPES[file.mimetype]) {
      cb(new Error('Only PNG, JPEG, WEBP or GIF images are allowed.'));
      return;
    }
    cb(null, true);
  }
});

const fileUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => {
      const ext = ALLOWED_FILE_TYPES[file.mimetype] || path.extname(file.originalname) || '';
      cb(null, `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${ext}`);
    }
  }),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_FILE_TYPES[file.mimetype]) {
      cb(new Error('File type not allowed.'));
      return;
    }
    cb(null, true);
  }
});

const db = new sqlite3.Database(dbPath);

function runSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function onRun(err) {
      if (err) {
        reject(err);
        return;
      }
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function getSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row || null);
    });
  });
}

function allSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows || []);
    });
  });
}

const ROLES = ['employee', 'admin', 'owner'];
const ROLE_RANK = { employee: 0, admin: 1, owner: 2 };
const LEAD_STAGES = ['new', 'contacted', 'qualified', 'proposal', 'won', 'lost', 'closed'];

async function columnExists(table, column) {
  const rows = await allSql(`PRAGMA table_info(${table})`);
  return rows.some((row) => row.name === column);
}

async function initDatabase() {
  await runSql(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'employee',
      name TEXT,
      bio TEXT,
      avatar_color TEXT,
      created_at TEXT,
      avatar_url TEXT,
      department TEXT,
      phone TEXT,
      location TEXT,
      active INTEGER DEFAULT 1,
      last_seen TEXT
    )
  `);

  if (!(await columnExists('users', 'department'))) {
    await runSql('ALTER TABLE users ADD COLUMN department TEXT');
  }
  if (!(await columnExists('users', 'phone'))) {
    await runSql('ALTER TABLE users ADD COLUMN phone TEXT');
  }
  if (!(await columnExists('users', 'location'))) {
    await runSql('ALTER TABLE users ADD COLUMN location TEXT');
  }
  if (!(await columnExists('users', 'active'))) {
    await runSql('ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1');
  }
  if (!(await columnExists('users', 'last_seen'))) {
    await runSql('ALTER TABLE users ADD COLUMN last_seen TEXT');
  }

  const AVATAR_PALETTE = ['#2d5fd6', '#0f766e', '#b45309', '#7c3aed', '#be123c', '#0f213e', '#0891b2', '#a16207'];
  const usersWithoutColor = await allSql('SELECT id FROM users WHERE avatar_color IS NULL');
  for (const row of usersWithoutColor) {
    const color = AVATAR_PALETTE[row.id % AVATAR_PALETTE.length];
    await runSql('UPDATE users SET avatar_color = ? WHERE id = ?', [color, row.id]);
  }

  await runSql("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL");

  await runSql(`
    CREATE TABLE IF NOT EXISTS site_content (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      headline TEXT,
      subtitle TEXT,
      cta_text TEXT
    )
  `);

  await runSql(`
    INSERT OR IGNORE INTO site_content (id, headline, subtitle, cta_text)
    VALUES (
      1,
      'Avara hjálpar fyrirtækjum að vaxa',
      'Við sjáum um bókhaldið svo þú getur einbeitt þér að vextinum.',
      'Hafa samband'
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS conversations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      name TEXT,
      created_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS conversation_members (
      conversation_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      PRIMARY KEY (conversation_id, user_id)
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL,
      sender_id INTEGER,
      sender_name TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      edited_at TEXT,
      deleted INTEGER DEFAULT 0,
      reply_to INTEGER,
      file_url TEXT,
      file_name TEXT,
      file_type TEXT,
      file_size INTEGER
    )
  `);

  if (!(await columnExists('messages', 'reply_to'))) {
    await runSql('ALTER TABLE messages ADD COLUMN reply_to INTEGER');
  }
  if (!(await columnExists('messages', 'file_url'))) {
    await runSql('ALTER TABLE messages ADD COLUMN file_url TEXT');
  }
  if (!(await columnExists('messages', 'file_name'))) {
    await runSql('ALTER TABLE messages ADD COLUMN file_name TEXT');
  }
  if (!(await columnExists('messages', 'file_type'))) {
    await runSql('ALTER TABLE messages ADD COLUMN file_type TEXT');
  }
  if (!(await columnExists('messages', 'file_size'))) {
    await runSql('ALTER TABLE messages ADD COLUMN file_size INTEGER');
  }

  const generalChannel = await getSql("SELECT id FROM conversations WHERE type = 'channel' AND name = 'general'");
  if (!generalChannel) {
    await runSql("INSERT INTO conversations (type, name) VALUES ('channel', 'general')");
  }

  await runSql(`
    CREATE TABLE IF NOT EXISTS leads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT DEFAULT 'new',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  if (!(await columnExists('leads', 'status'))) {
    await runSql("ALTER TABLE leads ADD COLUMN status TEXT DEFAULT 'new'");
  }

  await runSql(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor_name TEXT NOT NULL,
      action TEXT NOT NULL,
      details TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS pinned_messages (
      conversation_id INTEGER NOT NULL,
      message_id INTEGER NOT NULL,
      pinned_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (conversation_id, message_id)
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS conversation_reads (
      conversation_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      last_read_message_id INTEGER DEFAULT 0,
      PRIMARY KEY (conversation_id, user_id)
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS message_reactions (
      message_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (message_id, user_id, emoji)
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS tasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      status TEXT DEFAULT 'todo',
      priority TEXT DEFAULT 'medium',
      assignee_id INTEGER,
      created_by INTEGER,
      due_date TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      author_id INTEGER,
      author_name TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS calendar_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      start_time TEXT NOT NULL,
      end_time TEXT,
      created_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      file_url TEXT NOT NULL,
      file_type TEXT,
      file_size INTEGER,
      uploaded_by INTEGER,
      uploaded_by_name TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      link TEXT,
      read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS time_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      clock_in TEXT,
      clock_out TEXT,
      note TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS onboarding (
      user_id INTEGER PRIMARY KEY,
      completed INTEGER DEFAULT 0,
      step INTEGER DEFAULT 0,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS user_prefs (
      user_id INTEGER PRIMARY KEY,
      dark_mode INTEGER DEFAULT 0,
      language TEXT DEFAULT 'is',
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Notes / Wiki
  await runSql(`
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      author_id INTEGER,
      author_name TEXT,
      category TEXT DEFAULT 'general',
      is_wiki INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Leave requests
  await runSql(`
    CREATE TABLE IF NOT EXISTS leave_requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      user_name TEXT,
      type TEXT DEFAULT 'vacation',
      start_date TEXT NOT NULL,
      end_date TEXT NOT NULL,
      reason TEXT,
      status TEXT DEFAULT 'pending',
      approved_by INTEGER,
      approved_by_name TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Meeting notes
  await runSql(`
    CREATE TABLE IF NOT EXISTS meeting_notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      meeting_date TEXT,
      attendees TEXT,
      author_id INTEGER,
      author_name TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Custom fields
  await runSql(`
    CREATE TABLE IF NOT EXISTS custom_fields (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      entity_type TEXT NOT NULL,
      field_name TEXT NOT NULL,
      field_type TEXT DEFAULT 'text',
      field_label TEXT NOT NULL,
      required INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 2FA
  await runSql(`
    CREATE TABLE IF NOT EXISTS user_2fa (
      user_id INTEGER PRIMARY KEY,
      secret TEXT NOT NULL,
      enabled INTEGER DEFAULT 0,
      backup_codes TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Goals / OKRs
  await runSql(`
    CREATE TABLE IF NOT EXISTS goals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      owner_id INTEGER,
      owner_name TEXT,
      target_date TEXT,
      progress INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Training courses
  await runSql(`
    CREATE TABLE IF NOT EXISTS courses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      content TEXT,
      duration_minutes INTEGER,
      created_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS course_progress (
      user_id INTEGER NOT NULL,
      course_id INTEGER NOT NULL,
      progress INTEGER DEFAULT 0,
      completed INTEGER DEFAULT 0,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, course_id)
    )
  `);

  // ---- Schema v2: extended platform tables ----

  await runSql(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS login_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      email TEXT,
      success INTEGER DEFAULT 0,
      ip TEXT,
      user_agent TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS custom_field_values (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      field_id INTEGER NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id INTEGER NOT NULL,
      value TEXT,
      UNIQUE(field_id, entity_type, entity_id)
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS leave_balances (
      user_id INTEGER NOT NULL,
      year INTEGER NOT NULL,
      allowance REAL DEFAULT 25,
      used REAL DEFAULT 0,
      PRIMARY KEY (user_id, year)
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS expenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      user_name TEXT,
      title TEXT NOT NULL,
      category TEXT DEFAULT 'other',
      amount REAL NOT NULL,
      currency TEXT DEFAULT 'ISK',
      expense_date TEXT,
      receipt_url TEXT,
      receipt_name TEXT,
      note TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by INTEGER,
      reviewed_by_name TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cycle TEXT NOT NULL,
      subject_id INTEGER NOT NULL,
      subject_name TEXT,
      reviewer_id INTEGER,
      reviewer_name TEXT,
      type TEXT DEFAULT 'self',
      rating INTEGER,
      feedback TEXT,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS surveys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      question TEXT NOT NULL,
      anonymous INTEGER DEFAULT 1,
      active INTEGER DEFAULT 1,
      created_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS survey_responses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      survey_id INTEGER NOT NULL,
      user_id INTEGER,
      rating INTEGER,
      answer TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS jobs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      department TEXT,
      description TEXT,
      status TEXT DEFAULT 'open',
      created_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS applicants (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      job_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      email TEXT,
      phone TEXT,
      note TEXT,
      stage TEXT DEFAULT 'applied',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS shifts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      shift_date TEXT NOT NULL,
      start_time TEXT,
      end_time TEXT,
      note TEXT,
      created_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS subtasks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      done INTEGER DEFAULT 0,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS task_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER NOT NULL,
      user_id INTEGER,
      user_name TEXT,
      body TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS task_activity (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      task_id INTEGER NOT NULL,
      user_name TEXT,
      action TEXT NOT NULL,
      details TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS event_rsvps (
      event_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      status TEXT DEFAULT 'going',
      PRIMARY KEY (event_id, user_id)
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS document_versions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      document_id INTEGER NOT NULL,
      version INTEGER NOT NULL,
      file_url TEXT NOT NULL,
      file_size INTEGER,
      uploaded_by INTEGER,
      uploaded_by_name TEXT,
      note TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS saved_messages (
      user_id INTEGER NOT NULL,
      message_id INTEGER NOT NULL,
      saved_at TEXT DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id, message_id)
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS polls (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      conversation_id INTEGER NOT NULL,
      question TEXT NOT NULL,
      options TEXT NOT NULL,
      created_by INTEGER,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await runSql(`
    CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      option_index INTEGER NOT NULL,
      PRIMARY KEY (poll_id, user_id)
    )
  `);

  // Column migrations for existing tables
  if (!(await columnExists('tasks', 'parent_task_id'))) {
    await runSql('ALTER TABLE tasks ADD COLUMN parent_task_id INTEGER');
  }
  if (!(await columnExists('tasks', 'recurrence'))) {
    await runSql("ALTER TABLE tasks ADD COLUMN recurrence TEXT DEFAULT 'none'");
  }
  if (!(await columnExists('tasks', 'completed_at'))) {
    await runSql('ALTER TABLE tasks ADD COLUMN completed_at TEXT');
  }

  if (!(await columnExists('announcements', 'publish_at'))) {
    await runSql('ALTER TABLE announcements ADD COLUMN publish_at TEXT');
  }
  if (!(await columnExists('announcements', 'expires_at'))) {
    await runSql('ALTER TABLE announcements ADD COLUMN expires_at TEXT');
  }
  if (!(await columnExists('announcements', 'notified'))) {
    await runSql('ALTER TABLE announcements ADD COLUMN notified INTEGER DEFAULT 0');
  }

  if (!(await columnExists('documents', 'folder'))) {
    await runSql("ALTER TABLE documents ADD COLUMN folder TEXT DEFAULT ''");
  }
  if (!(await columnExists('documents', 'version'))) {
    await runSql('ALTER TABLE documents ADD COLUMN version INTEGER DEFAULT 1');
  }

  if (!(await columnExists('user_prefs', 'digest'))) {
    await runSql('ALTER TABLE user_prefs ADD COLUMN digest INTEGER DEFAULT 0');
  }
}

async function logAudit(actorName, action, details) {
  await runSql(
    'INSERT INTO audit_log (actor_name, action, details) VALUES (?, ?, ?)',
    [actorName, action, details || null]
  );
}

function requireAuth(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ ok: false, error: 'Unauthorized' });
}

const requireAdmin = requireAuth;

function requireElevated(req, res, next) {
  const role = req.session && req.session.user && req.session.user.role;
  if (role && ROLE_RANK[role] >= ROLE_RANK.admin) {
    return next();
  }
  return res.status(403).json({ ok: false, error: 'Forbidden' });
}

function requireOwner(req, res, next) {
  const role = req.session && req.session.user && req.session.user.role;
  if (role === 'owner') {
    return next();
  }
  return res.status(403).json({ ok: false, error: 'Forbidden' });
}

function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    email: row.email,
    name: row.name || row.email,
    role: row.role,
    bio: row.bio || '',
    avatarColor: row.avatar_color || '#2d5fd6',
    avatarUrl: row.avatar_url || null,
    createdAt: row.created_at || null,
    department: row.department || '',
    phone: row.phone || '',
    location: row.location || '',
    active: row.active !== 0,
    lastSeen: row.last_seen || null
  };
}

async function getGeneralChannelId() {
  const row = await getSql("SELECT id FROM conversations WHERE type = 'channel' AND name = 'general'");
  return row ? row.id : null;
}

async function canAccessConversation(conversationId, userId) {
  const convo = await getSql('SELECT id, type FROM conversations WHERE id = ?', [conversationId]);
  if (!convo) return false;
  if (convo.type === 'channel') return true;
  const member = await getSql(
    'SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?',
    [conversationId, userId]
  );
  return !!member;
}

async function getSiteContent() {
  const row = await getSql('SELECT headline, subtitle, cta_text AS ctaText FROM site_content WHERE id = 1');
  return row || {
    headline: 'Avara hjálpar fyrirtækjum að vaxa',
    subtitle: 'Við sjáum um bókhaldið svo þú getur einbeitt þér að vextinum.',
    ctaText: 'Hafa samband'
  };
}

async function createNotification(userId, type, title, body, link) {
  const result = await runSql(
    'INSERT INTO notifications (user_id, type, title, body, link) VALUES (?, ?, ?, ?, ?)',
    [userId, type, title, body || null, link || null]
  );
  try {
    const notification = await getSql('SELECT * FROM notifications WHERE id = ?', [result.id]);
    if (notification && typeof io !== 'undefined' && io) {
      io.to(`user:${userId}`).emit('notification', notification);
    }
  } catch (e) { /* socket push is best-effort */ }
}

async function getMeta(key) {
  const row = await getSql('SELECT value FROM meta WHERE key = ?', [key]);
  return row ? row.value : null;
}

async function setMeta(key, value) {
  await runSql(
    'INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value',
    [key, String(value)]
  );
}

// ---- Middleware ----

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(compression());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { ok: false, error: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { ok: false, error: 'Of margar innsendingar. Reyndu aftur síðar.' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  message: { ok: false, error: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false
});

app.set('trust proxy', 1);

const EXTRA_ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

function isDevOrigin(origin) {
  return origin && (origin.includes('localhost') || origin.includes('127.0.0.1'));
}

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (isDevOrigin(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  } else if (origin && EXTRA_ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  } else if (origin && req.path.startsWith('/api/public/')) {
    // Public read-only APIs may be consumed by any site
    res.header('Access-Control-Allow-Origin', '*');
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Named store so Socket.io can authenticate via the session cookie
const sessionStore = new session.MemoryStore();

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 30,
    secure: process.env.NODE_ENV === 'production'
  }
}));

// CSRF protection: verify Origin on mutating API requests
app.use('/api', (req, res, next) => {
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) return next();

  const origin = req.headers.origin;
  if (!origin) return next(); // same-origin request without Origin header

  let originHost = null;
  try {
    originHost = new URL(origin).hostname;
  } catch (e) {
    originHost = null;
  }

  const requestHost = (req.headers.host || '').split(':')[0];
  const allowed =
    isDevOrigin(origin) ||
    origin === 'null' || // file:// or privacy-mode clients (dev)
    originHost === requestHost ||
    EXTRA_ALLOWED_ORIGINS.includes(origin);

  if (!allowed) {
    return res.status(403).json({ ok: false, error: 'Cross-origin request rejected.' });
  }
  return next();
});

app.use(express.static(rootDir));
app.use('/avatars', express.static(avatarsDir));
app.use('/uploads', express.static(uploadsDir));

// ---- HTTP Server & Socket.io ----
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

io.on('connection', (socket) => {
  // Authenticate the socket using the HTTP session cookie (not client-supplied data)
  const cookies = parseCookies(socket.handshake.headers.cookie);
  const sid = getSessionIdFromCookie(cookies['connect.sid']);

  if (!sid) {
    socket.disconnect();
    return;
  }

  sessionStore.get(sid, (err, sessionData) => {
    if (err || !sessionData || !sessionData.user) {
      socket.disconnect();
      return;
    }
    attachAuthenticatedSocket(socket, sessionData.user);
  });
});

function attachAuthenticatedSocket(socket, sessionUser) {
  const userId = sessionUser.id;
  const userName = sessionUser.name || sessionUser.email;

  socket.join(`user:${userId}`);
  console.log(`Socket connected: user ${userId} (${userName})`);

  runSql('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [userId]).catch(() => {});

  socket.on('join-conversation', (conversationId) => {
    socket.join(`conversation:${conversationId}`);
  });

  socket.on('leave-conversation', (conversationId) => {
    socket.leave(`conversation:${conversationId}`);
  });

  socket.on('typing', (data) => {
    const { conversationId, isTyping } = data || {};
    if (!conversationId) return;
    socket.to(`conversation:${conversationId}`).emit('typing', {
      conversationId,
      userId,
      userName,
      isTyping: !!isTyping
    });
  });

  socket.on('message-sent', (data) => {
    const { conversationId, message } = data || {};
    if (!conversationId || !message) return;
    io.to(`conversation:${conversationId}`).emit('new-message', { conversationId, message });
  });

  socket.on('message-edited', (data) => {
    const { conversationId, message } = data || {};
    if (!conversationId || !message) return;
    io.to(`conversation:${conversationId}`).emit('message-updated', { conversationId, message });
  });

  socket.on('message-deleted', (data) => {
    const { conversationId, messageId } = data || {};
    if (!conversationId || !messageId) return;
    io.to(`conversation:${conversationId}`).emit('message-removed', { conversationId, messageId });
  });

  socket.on('reaction-updated', (data) => {
    const { conversationId, messageId, reactions } = data || {};
    if (!conversationId || !messageId) return;
    io.to(`conversation:${conversationId}`).emit('reactions-updated', { conversationId, messageId, reactions });
  });

  socket.on('disconnect', () => {
    console.log(`Socket disconnected: user ${userId}`);
  });
}

// ---- Health & Public ----

app.get('/api/health', (req, res) => {
  res.json({ ok: true, message: 'Server is running with updated code v3' });
});

app.get('/api/public/site-content', async (req, res) => {
  try {
    const data = await getSiteContent();
    res.json({ ok: true, data });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/admin/session', (req, res) => {
  res.json({
    ok: true,
    loggedIn: !!(req.session && req.session.user),
    user: req.session && req.session.user ? req.session.user : null
  });
});

// ---- Auth ----

app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const user = await getSql(
      'SELECT id, email, role, name, bio, avatar_color, avatar_url, created_at, department, phone, location, active, password FROM users WHERE email = ?',
      [normalizedEmail]
    );

    if (!user) {
      return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
    }

    if (user.active === 0) {
      return res.status(403).json({ ok: false, error: 'This account has been deactivated.' });
    }

    // Handle legacy plain-text passwords: compare directly, then upgrade to hashed
    let passwordMatch = false;
    if (user.password && (user.password.startsWith('$2a$') || user.password.startsWith('$2b$'))) {
      passwordMatch = await bcrypt.compare(String(password), user.password);
    } else {
      // Legacy plain-text password
      passwordMatch = user.password === String(password);
      if (passwordMatch) {
        // Upgrade to hashed password
        const hashed = await bcrypt.hash(String(password), 10);
        await runSql('UPDATE users SET password = ? WHERE id = ?', [hashed, user.id]);
      }
    }

    if (!passwordMatch) {
      await runSql(
        'INSERT INTO login_history (user_id, email, success, ip, user_agent) VALUES (?, ?, 0, ?, ?)',
        [user.id, normalizedEmail, req.ip || '', String(req.headers['user-agent'] || '').slice(0, 300)]
      );
      return res.status(401).json({ ok: false, error: 'Invalid email or password.' });
    }

    // Two-factor authentication check
    const twoFa = await getSql('SELECT secret, enabled, backup_codes FROM user_2fa WHERE user_id = ? AND enabled = 1', [user.id]);
    if (twoFa) {
      const { code } = req.body || {};
      let codeOk = verifyTotp(twoFa.secret, code);

      if (!codeOk && code) {
        // Try backup codes
        try {
          const backupCodes = JSON.parse(twoFa.backup_codes || '[]');
          const normalized = String(code).trim().toLowerCase();
          if (backupCodes.includes(normalized)) {
            codeOk = true;
            const remaining = backupCodes.filter((c) => c !== normalized);
            await runSql('UPDATE user_2fa SET backup_codes = ? WHERE user_id = ?', [JSON.stringify(remaining), user.id]);
          }
        } catch (e) { /* malformed backup codes */ }
      }

      if (!codeOk) {
        return res.status(401).json({ ok: false, error: 'Two-factor code is required or invalid.', needs2fa: true });
      }
    }

    req.session.regenerate(async (err) => {
      if (err) {
        return res.status(500).json({ ok: false, error: 'Session error.' });
      }
      req.session.user = publicUser(user);
      await runSql('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
      await runSql(
        'INSERT INTO login_history (user_id, email, success, ip, user_agent) VALUES (?, ?, 1, ?, ?)',
        [user.id, normalizedEmail, req.ip || '', String(req.headers['user-agent'] || '').slice(0, 300)]
      );
      const landingPage = ROLE_RANK[user.role] >= ROLE_RANK.admin ? 'admin.html' : 'Employee.html';
      return res.json({ ok: true, redirect: `/${landingPage}`, user: req.session.user });
    });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/signup', loginLimiter, async (req, res) => {
  try {
    const { fullname, email, password } = req.body || {};

    if (!fullname || !email || !password) {
      return res.status(400).json({ ok: false, error: 'Name, email and password are required.' });
    }

    if (String(password).length < 6) {
      return res.status(400).json({ ok: false, error: 'Password must be at least 6 characters.' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await getSql('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existing) {
      return res.status(409).json({ ok: false, error: 'An account with this email already exists.' });
    }

    const hashedPassword = await bcrypt.hash(String(password), 10);
    const result = await runSql(
      'INSERT INTO users (email, password, role, name) VALUES (?, ?, \'employee\', ?)',
      [normalizedEmail, hashedPassword, String(fullname).trim()]
    );
    const user = await getSql('SELECT id, email, role, name, bio, avatar_color, avatar_url, created_at, department, phone, location, active FROM users WHERE id = ?', [result.id]);

    req.session.regenerate(async (err) => {
      if (err) {
        return res.status(500).json({ ok: false, error: 'Session error.' });
      }
      req.session.user = publicUser(user);
      await runSql(
        'INSERT INTO login_history (user_id, email, success, ip, user_agent) VALUES (?, ?, 1, ?, ?)',
        [user.id, normalizedEmail, req.ip || '', String(req.headers['user-agent'] || '').slice(0, 300)]
      );
      return res.json({ ok: true, redirect: '/Employee.html', user: req.session.user });
    });
  } catch (error) {
    console.error('SIGNUP ERROR:', error);
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ ok: false, error: err.message });
    }
    return res.json({ ok: true });
  });
});

// ---- Password Reset ----

app.post('/api/forgot-password', loginLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) {
      return res.status(400).json({ ok: false, error: 'Email is required.' });
    }

    const user = await getSql('SELECT id, email, name FROM users WHERE email = ?', [String(email).trim().toLowerCase()]);
    if (!user) {
      // Do not reveal whether the account exists
      return res.json({ ok: true });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();

    await runSql(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)',
      [user.id, token, expiresAt]
    );

    const resetLink = `${req.protocol}://${req.get('host')}/reset-password?token=${token}`;
    console.log(`[PASSWORD RESET] ${user.email}: ${resetLink}`);

    await sendMail({
      to: user.email,
      subject: 'Endurstilla lykilorð — Avara',
      text: `Hæ ${user.name || ''},\n\nSmelltu á tengilinn hér að neðan til að endurstilla lykilorðið þitt (gildir í 60 mínútur):\n${resetLink}\n\nEf þú baðst ekki um þetta geturðu hunsað þennan póst.\n\n— Avara`,
      html: `<p>Hæ ${user.name || ''},</p><p>Smelltu á tengilinn hér að neðan til að endurstilla lykilorðið þitt (gildir í 60 mínútur):</p><p><a href="${resetLink}">Endurstilla lykilorð</a></p><p>Ef þú baðst ekki um þetta geturðu hunsað þennan póst.</p><p>— Avara</p>`
    });

    // Only expose the link directly when no SMTP is configured (dev convenience)
    return res.json({ ok: true, resetLink: mailTransport ? undefined : resetLink });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/reset-password', loginLimiter, async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword || String(newPassword).length < 6) {
      return res.status(400).json({ ok: false, error: 'Token and a new password (6+ characters) are required.' });
    }

    const reset = await getSql(
      'SELECT id, user_id, expires_at, used FROM password_resets WHERE token = ?',
      [token]
    );

    if (!reset || reset.used) {
      return res.status(400).json({ ok: false, error: 'Invalid or expired reset token.' });
    }

    if (new Date(reset.expires_at) < new Date()) {
      return res.status(400).json({ ok: false, error: 'Reset token has expired.' });
    }

    const hashed = await bcrypt.hash(String(newPassword), 10);
    await runSql('UPDATE users SET password = ? WHERE id = ?', [hashed, reset.user_id]);
    await runSql('UPDATE password_resets SET used = 1 WHERE id = ?', [reset.id]);

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Site Content ----

app.get('/api/admin/site-content', requireAdmin, async (req, res) => {
  try {
    const data = await getSiteContent();
    res.json({ ok: true, data });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/admin/site-content', requireAdmin, async (req, res) => {
  try {
    const { headline, subtitle, ctaText } = req.body || {};

    if (!headline || !subtitle || !ctaText) {
      return res.status(400).json({ ok: false, error: 'Headline, subtitle and CTA text are required.' });
    }

    await runSql(
      `INSERT INTO site_content (id, headline, subtitle, cta_text)
       VALUES (1, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         headline = excluded.headline,
         subtitle = excluded.subtitle,
         cta_text = excluded.cta_text`,
      [String(headline), String(subtitle), String(ctaText)]
    );

    return res.json({ ok: true, data: { headline, subtitle, ctaText } });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- User directory & profile ----

app.get('/api/users', requireAuth, async (req, res) => {
  try {
    const rows = await allSql('SELECT id, email, role, name, bio, avatar_color, avatar_url, created_at, department, phone, location, active, last_seen FROM users WHERE active = 1 ORDER BY name, email');
    res.json({ ok: true, users: rows.map(publicUser) });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/profile', requireAuth, async (req, res) => {
  try {
    const row = await getSql('SELECT id, email, role, name, bio, avatar_color, avatar_url, created_at, department, phone, location, active, last_seen FROM users WHERE id = ?', [req.session.user.id]);
    res.json({ ok: true, user: publicUser(row) });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const { name, bio, avatarColor, department, phone, location } = req.body || {};
    if (!name || !String(name).trim()) {
      return res.status(400).json({ ok: false, error: 'Name is required.' });
    }

    const ALLOWED_COLORS = ['#2d5fd6', '#0f766e', '#b45309', '#7c3aed', '#be123c', '#0f213e', '#0891b2', '#a16207'];
    const color = ALLOWED_COLORS.includes(avatarColor) ? avatarColor : null;

    await runSql(
      `UPDATE users SET name = ?, bio = ?, department = ?, phone = ?, location = ?${color ? ', avatar_color = ?' : ''} WHERE id = ?`,
      color
        ? [String(name).trim(), bio ? String(bio).trim().slice(0, 280) : null, department || null, phone || null, location || null, color, req.session.user.id]
        : [String(name).trim(), bio ? String(bio).trim().slice(0, 280) : null, department || null, phone || null, location || null, req.session.user.id]
    );
    const row = await getSql('SELECT id, email, role, name, bio, avatar_color, avatar_url, created_at, department, phone, location, active, last_seen FROM users WHERE id = ?', [req.session.user.id]);
    req.session.user = publicUser(row);
    return res.json({ ok: true, user: req.session.user });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/profile/password', requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword || String(newPassword).length < 6) {
      return res.status(400).json({ ok: false, error: 'Current password and a new password (6+ characters) are required.' });
    }

    const row = await getSql('SELECT password FROM users WHERE id = ?', [req.session.user.id]);
    if (!row) {
      return res.status(404).json({ ok: false, error: 'User not found.' });
    }

    const passwordMatch = await bcrypt.compare(String(currentPassword), row.password);
    if (!passwordMatch) {
      return res.status(403).json({ ok: false, error: 'Current password is incorrect.' });
    }

    const hashed = await bcrypt.hash(String(newPassword), 10);
    await runSql('UPDATE users SET password = ? WHERE id = ?', [hashed, req.session.user.id]);
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/profile/avatar', requireAuth, (req, res) => {
  avatarUpload.single('avatar')(req, res, async (uploadError) => {
    if (uploadError) {
      return res.status(400).json({ ok: false, error: uploadError.message || 'Unable to upload image.' });
    }

    if (!req.file) {
      return res.status(400).json({ ok: false, error: 'No image was uploaded.' });
    }

    try {
      const previous = await getSql('SELECT avatar_url FROM users WHERE id = ?', [req.session.user.id]);
      const avatarUrl = `/avatars/${req.file.filename}`;
      await runSql('UPDATE users SET avatar_url = ? WHERE id = ?', [avatarUrl, req.session.user.id]);

      if (previous && previous.avatar_url) {
        const oldPath = path.join(avatarsDir, path.basename(previous.avatar_url));
        fs.unlink(oldPath, () => {});
      }

      const row = await getSql('SELECT id, email, role, name, bio, avatar_color, avatar_url, created_at, department, phone, location, active, last_seen FROM users WHERE id = ?', [req.session.user.id]);
      req.session.user = publicUser(row);
      return res.json({ ok: true, user: req.session.user });
    } catch (error) {
      return res.status(500).json({ ok: false, error: error.message });
    }
  });
});

app.get('/api/profile/stats', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const [messages, conversations, groups, tasks] = await Promise.all([
      getSql('SELECT COUNT(*) AS count FROM messages WHERE sender_id = ? AND deleted = 0', [userId]),
      getSql('SELECT COUNT(*) AS count FROM conversation_members WHERE user_id = ?', [userId]),
      getSql(
        `SELECT COUNT(*) AS count FROM conversation_members m
         INNER JOIN conversations c ON c.id = m.conversation_id
         WHERE m.user_id = ? AND c.type = 'group'`,
        [userId]
      ),
      getSql('SELECT COUNT(*) AS count FROM tasks WHERE assignee_id = ?', [userId])
    ]);

    return res.json({
      ok: true,
      stats: {
        messagesSent: messages.count,
        conversations: conversations.count + 1,
        groups: groups.count,
        tasks: tasks.count
      }
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- User Preferences ----

app.get('/api/prefs', requireAuth, async (req, res) => {
  try {
    const prefs = await getSql('SELECT dark_mode AS darkMode, language FROM user_prefs WHERE user_id = ?', [req.session.user.id]);
    res.json({ ok: true, prefs: prefs || { darkMode: 0, language: 'is' } });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/prefs', requireAuth, async (req, res) => {
  try {
    const { darkMode, language } = req.body || {};
    await runSql(
      `INSERT INTO user_prefs (user_id, dark_mode, language, updated_at)
       VALUES (?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(user_id) DO UPDATE SET
         dark_mode = excluded.dark_mode,
         language = excluded.language,
         updated_at = CURRENT_TIMESTAMP`,
      [req.session.user.id, darkMode ? 1 : 0, language || 'is']
    );
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Admin: Users ----

app.get('/api/admin/users', requireElevated, async (req, res) => {
  try {
    const rows = await allSql('SELECT id, email, role, name, bio, avatar_color, avatar_url, created_at, department, phone, location, active, last_seen FROM users ORDER BY name, email');
    res.json({ ok: true, users: rows.map(publicUser) });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/admin/users/:id/role', requireOwner, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    const { role } = req.body || {};

    if (!ROLES.includes(role)) {
      return res.status(400).json({ ok: false, error: 'Invalid role.' });
    }

    const target = await getSql('SELECT id, email FROM users WHERE id = ?', [targetId]);
    if (!target) {
      return res.status(404).json({ ok: false, error: 'User not found.' });
    }

    await runSql('UPDATE users SET role = ? WHERE id = ?', [role, targetId]);
    const updated = await getSql('SELECT id, email, role, name, bio, avatar_color, avatar_url, created_at, department, phone, location, active, last_seen FROM users WHERE id = ?', [targetId]);
    await logAudit(
      req.session.user.name || req.session.user.email,
      'role_change',
      `Set ${target.email}'s role to ${role}`
    );
    return res.json({ ok: true, user: publicUser(updated) });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/admin/users/:id', requireOwner, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    if (targetId === req.session.user.id) {
      return res.status(400).json({ ok: false, error: 'You cannot delete your own account.' });
    }

    const target = await getSql('SELECT id, email FROM users WHERE id = ?', [targetId]);
    if (!target) {
      return res.status(404).json({ ok: false, error: 'User not found.' });
    }

    await runSql('DELETE FROM users WHERE id = ?', [targetId]);
    await runSql('DELETE FROM conversation_members WHERE user_id = ?', [targetId]);
    await runSql('DELETE FROM conversation_reads WHERE user_id = ?', [targetId]);
    await runSql('DELETE FROM message_reactions WHERE user_id = ?', [targetId]);
    await runSql('DELETE FROM notifications WHERE user_id = ?', [targetId]);
    await runSql('DELETE FROM user_prefs WHERE user_id = ?', [targetId]);
    await runSql('DELETE FROM onboarding WHERE user_id = ?', [targetId]);
    await runSql('DELETE FROM time_entries WHERE user_id = ?', [targetId]);

    await logAudit(
      req.session.user.name || req.session.user.email,
      'user_delete',
      `Deleted user ${target.email}`
    );

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/admin/users/:id/active', requireOwner, async (req, res) => {
  try {
    const targetId = Number(req.params.id);
    const { active } = req.body || {};

    if (targetId === req.session.user.id) {
      return res.status(400).json({ ok: false, error: 'You cannot deactivate your own account.' });
    }

    const target = await getSql('SELECT id, email FROM users WHERE id = ?', [targetId]);
    if (!target) {
      return res.status(404).json({ ok: false, error: 'User not found.' });
    }

    await runSql('UPDATE users SET active = ? WHERE id = ?', [active ? 1 : 0, targetId]);
    await logAudit(
      req.session.user.name || req.session.user.email,
      active ? 'user_activate' : 'user_deactivate',
      `${active ? 'Activated' : 'Deactivated'} user ${target.email}`
    );

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Public contact form & leads ----

app.post('/api/contact', contactLimiter, async (req, res) => {
  try {
    const { name, email, message, captchaAnswer } = req.body || {};

    if (typeof name !== 'string' || typeof email !== 'string' || typeof message !== 'string') {
      return res.status(400).json({ ok: false, error: 'Fylltu út nafn, netfang og skilaboð.' });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim();
    const cleanMessage = message.trim();

    if (!cleanName || cleanName.length > 200 ||
        !cleanEmail || cleanEmail.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail) ||
        !cleanMessage || cleanMessage.length > 4000) {
      return res.status(400).json({ ok: false, error: 'Athugaðu að upplýsingarnar séu rétt útfylltar.' });
    }

    if (captchaAnswer !== '7') {
      return res.status(400).json({ ok: false, error: 'Rangt svar við öryggisspurningu, reyndu aftur.' });
    }

    const emailSent = await sendMail({
      to: 'avara@avara.is',
      replyTo: cleanEmail,
      subject: 'Ný fyrirspurn á vefsíðu Avara',
      text: `Ný fyrirspurn:\n\nNafn: ${cleanName}\nNetfang: ${cleanEmail}\n\nSkilaboð:\n${cleanMessage}`
    });

    if (!emailSent) {
      return res.status(503).json({ ok: false, error: 'Ekki tókst að senda skilaboðin. Reyndu aftur síðar.' });
    }

    await runSql(
      'INSERT INTO leads (name, email, message) VALUES (?, ?, ?)',
      [cleanName, cleanEmail, cleanMessage]
    );

    try {
      const admins = await allSql("SELECT id FROM users WHERE role IN ('admin', 'owner') AND active = 1");
      for (const admin of admins) {
        await createNotification(admin.id, 'lead', 'Ný fyrirspurn', `${cleanName} — ${cleanMessage.slice(0, 80)}`, '/Dashboard.html');
      }
    } catch (notificationError) {
      console.error('Contact notification failed:', notificationError.message);
    }

    return res.json({ ok: true });
  } catch (error) {
    console.error('Contact submission failed:', error.message);
    return res.status(500).json({ ok: false, error: 'Villa kom upp við sendingu skilaboðanna.' });
  }
});

app.get('/api/admin/leads', requireElevated, async (req, res) => {
  try {
    const { status } = req.query;
    let sql = 'SELECT id, name, email, message, status, created_at AS createdAt FROM leads';
    const params = [];
    if (status && LEAD_STAGES.includes(status)) {
      sql += ' WHERE status = ?';
      params.push(status);
    }
    sql += ' ORDER BY id DESC';
    const rows = await allSql(sql, params);
    return res.json({ ok: true, leads: rows });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/admin/leads/:id/status', requireElevated, async (req, res) => {
  try {
    const leadId = Number(req.params.id);
    const { status } = req.body || {};

    if (!LEAD_STAGES.includes(status)) {
      return res.status(400).json({ ok: false, error: 'Invalid status.' });
    }

    const lead = await getSql('SELECT id, name FROM leads WHERE id = ?', [leadId]);
    if (!lead) {
      return res.status(404).json({ ok: false, error: 'Lead not found.' });
    }

    await runSql('UPDATE leads SET status = ? WHERE id = ?', [status, leadId]);
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/admin/leads/:id', requireElevated, async (req, res) => {
  try {
    const leadId = Number(req.params.id);
    await runSql('DELETE FROM leads WHERE id = ?', [leadId]);
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Admin dashboard: stats & audit log ----

app.get('/api/admin/stats', requireElevated, async (req, res) => {
  try {
    const [users, groups, dms, messages, leads, tasks, announcements, documents] = await Promise.all([
      getSql('SELECT COUNT(*) AS count FROM users WHERE active = 1'),
      getSql("SELECT COUNT(*) AS count FROM conversations WHERE type = 'group'"),
      getSql("SELECT COUNT(*) AS count FROM conversations WHERE type = 'dm'"),
      getSql('SELECT COUNT(*) AS count FROM messages WHERE deleted = 0'),
      getSql('SELECT COUNT(*) AS count FROM leads'),
      getSql('SELECT COUNT(*) AS count FROM tasks'),
      getSql('SELECT COUNT(*) AS count FROM announcements'),
      getSql('SELECT COUNT(*) AS count FROM documents')
    ]);

    return res.json({
      ok: true,
      stats: {
        users: users.count,
        groups: groups.count,
        directMessages: dms.count,
        messages: messages.count,
        leads: leads.count,
        tasks: tasks.count,
        announcements: announcements.count,
        documents: documents.count
      }
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/admin/analytics', requireElevated, async (req, res) => {
  try {
    const messagesPerDay = await allSql(`
      SELECT date(created_at) AS day, COUNT(*) AS count
      FROM messages WHERE deleted = 0 AND created_at >= date('now', '-14 days')
      GROUP BY date(created_at) ORDER BY day
    `);

    const signupsPerDay = await allSql(`
      SELECT date(created_at) AS day, COUNT(*) AS count
      FROM users WHERE created_at >= date('now', '-14 days')
      GROUP BY date(created_at) ORDER BY day
    `);

    const activeUsers = await getSql(`
      SELECT COUNT(DISTINCT sender_id) AS count FROM messages
      WHERE created_at >= date('now', '-7 days') AND sender_id IS NOT NULL
    `);

    const topUsers = await allSql(`
      SELECT sender_name AS name, COUNT(*) AS count
      FROM messages WHERE deleted = 0 AND sender_id IS NOT NULL
      GROUP BY sender_id ORDER BY count DESC LIMIT 5
    `);

    return res.json({
      ok: true,
      analytics: {
        messagesPerDay,
        signupsPerDay,
        activeUsers: activeUsers.count,
        topUsers
      }
    });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/admin/audit-log', requireElevated, async (req, res) => {
  try {
    const { action, actor, limit = 200 } = req.query;
    let sql = 'SELECT id, actor_name AS actorName, action, details, created_at AS createdAt FROM audit_log';
    const params = [];
    const conditions = [];

    if (action) {
      conditions.push('action = ?');
      params.push(action);
    }
    if (actor) {
      conditions.push('actor_name LIKE ?');
      params.push(`%${actor}%`);
    }
    if (conditions.length) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }
    sql += ' ORDER BY id DESC LIMIT ?';
    params.push(Math.min(Number(limit) || 200, 500));

    const rows = await allSql(sql, params);
    return res.json({ ok: true, entries: rows });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Conversations ----

app.get('/api/conversations', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const generalId = await getGeneralChannelId();

    const memberOf = await allSql(
      `SELECT c.id, c.type, c.name FROM conversations c
       INNER JOIN conversation_members m ON m.conversation_id = c.id
       WHERE m.user_id = ?`,
      [userId]
    );

    const conversations = [{ id: generalId, type: 'channel', name: 'general' }, ...memberOf];

    const enriched = await Promise.all(conversations.map(async (convo) => {
      let displayName = convo.name;
      let otherUser = null;

      if (convo.type === 'dm') {
        const other = await getSql(
          `SELECT u.id, u.name, u.email, u.avatar_color, u.avatar_url FROM conversation_members m
           INNER JOIN users u ON u.id = m.user_id
           WHERE m.conversation_id = ? AND m.user_id != ?`,
          [convo.id, userId]
        );
        displayName = other ? (other.name || other.email) : 'Direct Message';
        otherUser = other ? {
          id: other.id,
          avatarColor: other.avatar_color || '#2d5fd6',
          avatarUrl: other.avatar_url || null
        } : null;
      }

      return { id: convo.id, type: convo.type, name: displayName, otherUser };
    }));

    return res.json({ ok: true, conversations: enriched });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/conversations/dm', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const targetId = Number((req.body || {}).userId);

    if (!targetId || targetId === userId) {
      return res.status(400).json({ ok: false, error: 'A valid target user is required.' });
    }

    const target = await getSql('SELECT id FROM users WHERE id = ?', [targetId]);
    if (!target) {
      return res.status(404).json({ ok: false, error: 'User not found.' });
    }

    const existing = await getSql(
      `SELECT c.id FROM conversations c
       INNER JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = ?
       INNER JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = ?
       WHERE c.type = 'dm'`,
      [userId, targetId]
    );

    let conversationId = existing ? existing.id : null;

    if (!conversationId) {
      const created = await runSql(
        "INSERT INTO conversations (type, created_by) VALUES ('dm', ?)",
        [userId]
      );
      conversationId = created.id;
      await runSql('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)', [conversationId, userId]);
      await runSql('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)', [conversationId, targetId]);
    }

    return res.json({ ok: true, conversationId });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/conversations/group', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const { name, memberIds } = req.body || {};

    if (!name || !String(name).trim()) {
      return res.status(400).json({ ok: false, error: 'Group name is required.' });
    }

    const ids = Array.isArray(memberIds) ? memberIds.map(Number).filter((id) => Number.isInteger(id) && id !== userId) : [];
    const uniqueIds = Array.from(new Set(ids));

    const created = await runSql(
      "INSERT INTO conversations (type, name, created_by) VALUES ('group', ?, ?)",
      [String(name).trim(), userId]
    );

    await runSql('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)', [created.id, userId]);
    for (const memberId of uniqueIds) {
      const exists = await getSql('SELECT id FROM users WHERE id = ?', [memberId]);
      if (exists) {
        await runSql('INSERT OR IGNORE INTO conversation_members (conversation_id, user_id) VALUES (?, ?)', [created.id, memberId]);
      }
    }

    return res.json({ ok: true, conversationId: created.id });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/conversations/:id/messages', requireAuth, async (req, res) => {
  try {
    const conversationId = Number(req.params.id);
    const userId = req.session.user.id;

    if (!(await canAccessConversation(conversationId, userId))) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    const rows = await allSql(
      `SELECT id, conversation_id AS conversationId, sender_id AS senderId, sender_name AS senderName,
              body, created_at AS createdAt, edited_at AS editedAt, deleted,
              reply_to AS replyTo, file_url AS fileUrl, file_name AS fileName,
              file_type AS fileType, file_size AS fileSize
       FROM messages WHERE conversation_id = ? ORDER BY id ASC`,
      [conversationId]
    );

    const messageIds = rows.filter(m => !m.deleted).map(m => m.id);
    let reactions = {};
    if (messageIds.length) {
      const placeholders = messageIds.map(() => '?').join(',');
      const reactionRows = await allSql(
        `SELECT message_id AS messageId, user_id AS userId, emoji FROM message_reactions
         WHERE message_id IN (${placeholders})`,
        messageIds
      );
      reactions = reactionRows.reduce((acc, r) => {
        if (!acc[r.messageId]) acc[r.messageId] = [];
        acc[r.messageId].push({ userId: r.userId, emoji: r.emoji });
        return acc;
      }, {});
    }

    const enriched = rows.map(m => ({
      ...m,
      reactions: reactions[m.id] || []
    }));

    return res.json({ ok: true, messages: enriched });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/conversations/:id/messages', requireAuth, async (req, res) => {
  try {
    const conversationId = Number(req.params.id);
    const userId = req.session.user.id;
    const { message, replyTo } = req.body || {};

    if (!message || !String(message).trim()) {
      return res.status(400).json({ ok: false, error: 'Message is required.' });
    }

    if (!(await canAccessConversation(conversationId, userId))) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    const senderName = req.session.user.name || req.session.user.email;
    const result = await runSql(
      'INSERT INTO messages (conversation_id, sender_id, sender_name, body, reply_to) VALUES (?, ?, ?, ?, ?)',
      [conversationId, userId, senderName, String(message).trim(), replyTo || null]
    );

    const inserted = await getSql(
      `SELECT id, conversation_id AS conversationId, sender_id AS senderId, sender_name AS senderName,
              body, created_at AS createdAt, edited_at AS editedAt, deleted,
              reply_to AS replyTo, file_url AS fileUrl, file_name AS fileName,
              file_type AS fileType, file_size AS fileSize
       FROM messages WHERE id = ?`,
      [result.id]
    );

    io.to(`conversation:${conversationId}`).emit('new-message', {
      conversationId,
      message: { ...inserted, reactions: [] }
    });

    const members = await allSql(
      'SELECT user_id FROM conversation_members WHERE conversation_id = ? AND user_id != ?',
      [conversationId, userId]
    );
    for (const member of members) {
      await createNotification(
        member.user_id,
        'message',
        senderName,
        String(message).trim().slice(0, 100),
        `/chat.html?conversation=${conversationId}`
      );
    }

    return res.json({ ok: true, message: { ...inserted, reactions: [] } });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/conversations/:id/messages/file', requireAuth, (req, res) => {
  fileUpload.single('file')(req, res, async (uploadError) => {
    if (uploadError) {
      return res.status(400).json({ ok: false, error: uploadError.message || 'Unable to upload file.' });
    }

    if (!req.file) {
      return res.status(400).json({ ok: false, error: 'No file was uploaded.' });
    }

    try {
      const conversationId = Number(req.params.id);
      const userId = req.session.user.id;

      if (!(await canAccessConversation(conversationId, userId))) {
        return res.status(403).json({ ok: false, error: 'Forbidden' });
      }

      const senderName = req.session.user.name || req.session.user.email;
      const fileUrl = `/uploads/${req.file.filename}`;
      const result = await runSql(
        `INSERT INTO messages (conversation_id, sender_id, sender_name, body, file_url, file_name, file_type, file_size)
         VALUES (?, ?, ?, '', ?, ?, ?, ?)`,
        [conversationId, userId, senderName, fileUrl, req.file.originalname, req.file.mimetype, req.file.size]
      );

      const inserted = await getSql(
        `SELECT id, conversation_id AS conversationId, sender_id AS senderId, sender_name AS senderName,
                body, created_at AS createdAt, edited_at AS editedAt, deleted,
                reply_to AS replyTo, file_url AS fileUrl, file_name AS fileName,
                file_type AS fileType, file_size AS fileSize
         FROM messages WHERE id = ?`,
        [result.id]
      );

      io.to(`conversation:${conversationId}`).emit('new-message', {
        conversationId,
        message: { ...inserted, reactions: [] }
      });

      return res.json({ ok: true, message: { ...inserted, reactions: [] } });
    } catch (error) {
      return res.status(500).json({ ok: false, error: error.message });
    }
  });
});

app.put('/api/messages/:id', requireAuth, async (req, res) => {
  try {
    const messageId = Number(req.params.id);
    const userId = req.session.user.id;
    const { message } = req.body || {};

    if (!message || !String(message).trim()) {
      return res.status(400).json({ ok: false, error: 'Message is required.' });
    }

    const existing = await getSql('SELECT id, sender_id AS senderId, deleted, conversation_id AS conversationId FROM messages WHERE id = ?', [messageId]);
    if (!existing || existing.deleted) {
      return res.status(404).json({ ok: false, error: 'Message not found.' });
    }

    if (existing.senderId !== userId) {
      return res.status(403).json({ ok: false, error: 'You can only edit your own messages.' });
    }

    await runSql(
      "UPDATE messages SET body = ?, edited_at = CURRENT_TIMESTAMP WHERE id = ?",
      [String(message).trim(), messageId]
    );

    const updated = await getSql(
      `SELECT id, conversation_id AS conversationId, sender_id AS senderId, sender_name AS senderName,
              body, created_at AS createdAt, edited_at AS editedAt, deleted,
              reply_to AS replyTo, file_url AS fileUrl, file_name AS fileName,
              file_type AS fileType, file_size AS fileSize
       FROM messages WHERE id = ?`,
      [messageId]
    );

    io.to(`conversation:${existing.conversationId}`).emit('message-updated', {
      conversationId: existing.conversationId,
      message: { ...updated, reactions: [] }
    });

    return res.json({ ok: true, message: { ...updated, reactions: [] } });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/messages/:id', requireAuth, async (req, res) => {
  try {
    const messageId = Number(req.params.id);
    const userId = req.session.user.id;
    const role = req.session.user.role;

    const existing = await getSql('SELECT id, sender_id AS senderId, deleted, conversation_id AS conversationId FROM messages WHERE id = ?', [messageId]);
    if (!existing || existing.deleted) {
      return res.status(404).json({ ok: false, error: 'Message not found.' });
    }

    const isOwnMessage = existing.senderId === userId;
    const isElevated = ROLE_RANK[role] >= ROLE_RANK.admin;

    if (!isOwnMessage && !isElevated) {
      return res.status(403).json({ ok: false, error: 'You do not have permission to delete this message.' });
    }

    await runSql("UPDATE messages SET deleted = 1, body = '' WHERE id = ?", [messageId]);
    await runSql('DELETE FROM pinned_messages WHERE message_id = ?', [messageId]);
    await runSql('DELETE FROM message_reactions WHERE message_id = ?', [messageId]);

    io.to(`conversation:${existing.conversationId}`).emit('message-removed', {
      conversationId: existing.conversationId,
      messageId
    });

    if (!isOwnMessage) {
      await logAudit(
        req.session.user.name || req.session.user.email,
        'message_delete',
        `Deleted message #${messageId} from ${existing.senderId ? 'user #' + existing.senderId : 'unknown user'}`
      );
    }

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Message Reactions ----

app.post('/api/messages/:id/reactions', requireAuth, async (req, res) => {
  try {
    const messageId = Number(req.params.id);
    const userId = req.session.user.id;
    const { emoji } = req.body || {};

    if (!emoji) {
      return res.status(400).json({ ok: false, error: 'Emoji is required.' });
    }

    const message = await getSql('SELECT id, conversation_id AS conversationId, deleted FROM messages WHERE id = ?', [messageId]);
    if (!message || message.deleted) {
      return res.status(404).json({ ok: false, error: 'Message not found.' });
    }

    if (!(await canAccessConversation(message.conversationId, userId))) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    const existing = await getSql(
      'SELECT 1 FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?',
      [messageId, userId, emoji]
    );

    if (existing) {
      await runSql('DELETE FROM message_reactions WHERE message_id = ? AND user_id = ? AND emoji = ?', [messageId, userId, emoji]);
    } else {
      await runSql(
        'INSERT OR IGNORE INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)',
        [messageId, userId, emoji]
      );
    }

    const reactions = await allSql(
      'SELECT user_id AS userId, emoji FROM message_reactions WHERE message_id = ?',
      [messageId]
    );

    io.to(`conversation:${message.conversationId}`).emit('reactions-updated', {
      conversationId: message.conversationId,
      messageId,
      reactions
    });

    return res.json({ ok: true, reactions });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Pinned messages ----

app.get('/api/conversations/:id/pins', requireAuth, async (req, res) => {
  try {
    const conversationId = Number(req.params.id);
    if (!(await canAccessConversation(conversationId, req.session.user.id))) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    const rows = await allSql(
      `SELECT m.id, m.sender_name AS senderName, m.body, m.created_at AS createdAt
       FROM pinned_messages p INNER JOIN messages m ON m.id = p.message_id
       WHERE p.conversation_id = ? ORDER BY p.created_at DESC`,
      [conversationId]
    );

    return res.json({ ok: true, pins: rows });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/messages/:id/pin', requireAuth, async (req, res) => {
  try {
    const messageId = Number(req.params.id);
    const message = await getSql('SELECT id, conversation_id AS conversationId, deleted FROM messages WHERE id = ?', [messageId]);

    if (!message || message.deleted) {
      return res.status(404).json({ ok: false, error: 'Message not found.' });
    }

    if (!(await canAccessConversation(message.conversationId, req.session.user.id))) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    await runSql(
      'INSERT OR IGNORE INTO pinned_messages (conversation_id, message_id, pinned_by) VALUES (?, ?, ?)',
      [message.conversationId, messageId, req.session.user.id]
    );

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/messages/:id/pin', requireAuth, async (req, res) => {
  try {
    const messageId = Number(req.params.id);
    await runSql('DELETE FROM pinned_messages WHERE message_id = ?', [messageId]);
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Read receipts / unread counts ----

app.post('/api/conversations/:id/read', requireAuth, async (req, res) => {
  try {
    const conversationId = Number(req.params.id);
    const userId = req.session.user.id;

    if (!(await canAccessConversation(conversationId, userId))) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    const latest = await getSql('SELECT MAX(id) AS maxId FROM messages WHERE conversation_id = ?', [conversationId]);
    const lastReadId = (latest && latest.maxId) || 0;

    await runSql(
      `INSERT INTO conversation_reads (conversation_id, user_id, last_read_message_id)
       VALUES (?, ?, ?)
       ON CONFLICT(conversation_id, user_id) DO UPDATE SET last_read_message_id = excluded.last_read_message_id`,
      [conversationId, userId, lastReadId]
    );

    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/conversations/unread-counts', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const generalId = await getGeneralChannelId();

    const memberOf = await allSql(
      'SELECT conversation_id AS id FROM conversation_members WHERE user_id = ?',
      [userId]
    );
    const conversationIds = [generalId, ...memberOf.map((r) => r.id)];

    const counts = {};
    for (const conversationId of conversationIds) {
      const readRow = await getSql(
        'SELECT last_read_message_id AS lastReadId FROM conversation_reads WHERE conversation_id = ? AND user_id = ?',
        [conversationId, userId]
      );
      const lastReadId = readRow ? readRow.lastReadId : 0;
      const unread = await getSql(
        'SELECT COUNT(*) AS count FROM messages WHERE conversation_id = ? AND deleted = 0 AND id > ? AND sender_id != ?',
        [conversationId, lastReadId, userId]
      );
      counts[conversationId] = unread.count;
    }

    return res.json({ ok: true, counts });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Message search ----

app.get('/api/conversations/:id/search', requireAuth, async (req, res) => {
  try {
    const conversationId = Number(req.params.id);
    const term = String(req.query.q || '').trim();

    if (!(await canAccessConversation(conversationId, req.session.user.id))) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    if (!term) {
      return res.json({ ok: true, messages: [] });
    }

    const rows = await allSql(
      `SELECT id, conversation_id AS conversationId, sender_id AS senderId, sender_name AS senderName,
              body, created_at AS createdAt, edited_at AS editedAt, deleted
       FROM messages
       WHERE conversation_id = ? AND deleted = 0 AND body LIKE ?
       ORDER BY id DESC LIMIT 50`,
      [conversationId, `%${term}%`]
    );

    return res.json({ ok: true, messages: rows });
  } catch (error) {
    return res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Tasks / Kanban ----

app.get('/api/tasks', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const role = req.session.user.role;
    let rows;
    if (ROLE_RANK[role] >= ROLE_RANK.admin) {
      rows = await allSql(`
        SELECT t.*, u.name AS assigneeName, u.avatar_color AS assigneeColor
        FROM tasks t LEFT JOIN users u ON u.id = t.assignee_id
        ORDER BY t.created_at DESC
      `);
    } else {
      rows = await allSql(`
        SELECT t.*, u.name AS assigneeName, u.avatar_color AS assigneeColor
        FROM tasks t LEFT JOIN users u ON u.id = t.assignee_id
        WHERE t.assignee_id = ? OR t.created_by = ?
        ORDER BY t.created_at DESC
      `, [userId, userId]);
    }
    res.json({ ok: true, tasks: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const { title, description, status, priority, assigneeId, dueDate } = req.body || {};
    if (!title || !String(title).trim()) {
      return res.status(400).json({ ok: false, error: 'Task title is required.' });
    }

    const result = await runSql(
      `INSERT INTO tasks (title, description, status, priority, assignee_id, created_by, due_date)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        String(title).trim(),
        description || null,
        status || 'todo',
        priority || 'medium',
        assigneeId || null,
        req.session.user.id,
        dueDate || null
      ]
    );

    if (assigneeId && assigneeId !== req.session.user.id) {
      await createNotification(
        assigneeId,
        'task',
        'Nýtt verkefni',
        String(title).trim(),
        '/tasks.html'
      );
    }

    const task = await getSql(`
      SELECT t.*, u.name AS assigneeName, u.avatar_color AS assigneeColor
      FROM tasks t LEFT JOIN users u ON u.id = t.assignee_id
      WHERE t.id = ?
    `, [result.id]);

    res.json({ ok: true, task });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const taskId = Number(req.params.id);
    const { title, description, status, priority, assigneeId, dueDate } = req.body || {};

    const existing = await getSql('SELECT id, assignee_id FROM tasks WHERE id = ?', [taskId]);
    if (!existing) {
      return res.status(404).json({ ok: false, error: 'Task not found.' });
    }

    await runSql(
      `UPDATE tasks SET title = ?, description = ?, status = ?, priority = ?, assignee_id = ?, due_date = ? WHERE id = ?`,
      [
        title || existing.title,
        description !== undefined ? description : null,
        status || 'todo',
        priority || 'medium',
        assigneeId !== undefined ? assigneeId : existing.assignee_id,
        dueDate !== undefined ? dueDate : null,
        taskId
      ]
    );

    const task = await getSql(`
      SELECT t.*, u.name AS assigneeName, u.avatar_color AS assigneeColor
      FROM tasks t LEFT JOIN users u ON u.id = t.assignee_id
      WHERE t.id = ?
    `, [taskId]);

    res.json({ ok: true, task });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const taskId = Number(req.params.id);
    const task = await getSql('SELECT id, created_by FROM tasks WHERE id = ?', [taskId]);
    if (!task) {
      return res.status(404).json({ ok: false, error: 'Task not found.' });
    }

    const role = req.session.user.role;
    if (task.created_by !== req.session.user.id && ROLE_RANK[role] < ROLE_RANK.admin) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    await runSql('DELETE FROM tasks WHERE id = ?', [taskId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Announcements ----

app.get('/api/announcements', requireAuth, async (req, res) => {
  try {
    const rows = await allSql('SELECT * FROM announcements ORDER BY created_at DESC LIMIT 20');
    res.json({ ok: true, announcements: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/announcements', requireAuth, async (req, res) => {
  try {
    const { title, body } = req.body || {};
    if (!title || !body) {
      return res.status(400).json({ ok: false, error: 'Title and body are required.' });
    }

    const result = await runSql(
      'INSERT INTO announcements (title, body, author_id, author_name) VALUES (?, ?, ?, ?)',
      [String(title).trim(), String(body).trim(), req.session.user.id, req.session.user.name || req.session.user.email]
    );

    const announcement = await getSql('SELECT * FROM announcements WHERE id = ?', [result.id]);

    const users = await allSql('SELECT id FROM users WHERE active = 1');
    for (const user of users) {
      if (user.id !== req.session.user.id) {
        await createNotification(user.id, 'announcement', String(title).trim(), String(body).trim().slice(0, 100), '/announcements.html');
      }
    }

    res.json({ ok: true, announcement });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/announcements/:id', requireElevated, async (req, res) => {
  try {
    const announcementId = Number(req.params.id);
    await runSql('DELETE FROM announcements WHERE id = ?', [announcementId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Calendar Events ----

app.get('/api/calendar', requireAuth, async (req, res) => {
  try {
    const rows = await allSql('SELECT * FROM calendar_events ORDER BY start_time ASC');
    res.json({ ok: true, events: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/calendar', requireAuth, async (req, res) => {
  try {
    const { title, description, startTime, endTime } = req.body || {};
    if (!title || !startTime) {
      return res.status(400).json({ ok: false, error: 'Title and start time are required.' });
    }

    const result = await runSql(
      'INSERT INTO calendar_events (title, description, start_time, end_time, created_by) VALUES (?, ?, ?, ?, ?)',
      [String(title).trim(), description || null, startTime, endTime || null, req.session.user.id]
    );

    const event = await getSql('SELECT * FROM calendar_events WHERE id = ?', [result.id]);
    res.json({ ok: true, event });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/calendar/:id', requireAuth, async (req, res) => {
  try {
    const eventId = Number(req.params.id);
    const event = await getSql('SELECT id, created_by FROM calendar_events WHERE id = ?', [eventId]);
    if (!event) {
      return res.status(404).json({ ok: false, error: 'Event not found.' });
    }

    const role = req.session.user.role;
    if (event.created_by !== req.session.user.id && ROLE_RANK[role] < ROLE_RANK.admin) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    await runSql('DELETE FROM calendar_events WHERE id = ?', [eventId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Documents ----

app.get('/api/documents', requireAuth, async (req, res) => {
  try {
    const rows = await allSql('SELECT * FROM documents ORDER BY created_at DESC');
    res.json({ ok: true, documents: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/documents', requireAuth, (req, res) => {
  fileUpload.single('file')(req, res, async (uploadError) => {
    if (uploadError) {
      return res.status(400).json({ ok: false, error: uploadError.message || 'Unable to upload file.' });
    }

    if (!req.file) {
      return res.status(400).json({ ok: false, error: 'No file was uploaded.' });
    }

    try {
      const fileUrl = `/uploads/${req.file.filename}`;
      const result = await runSql(
        'INSERT INTO documents (name, file_url, file_type, file_size, uploaded_by, uploaded_by_name) VALUES (?, ?, ?, ?, ?, ?)',
        [req.file.originalname, fileUrl, req.file.mimetype, req.file.size, req.session.user.id, req.session.user.name || req.session.user.email]
      );

      const doc = await getSql('SELECT * FROM documents WHERE id = ?', [result.id]);
      res.json({ ok: true, document: doc });
    } catch (error) {
      res.status(500).json({ ok: false, error: error.message });
    }
  });
});

app.delete('/api/documents/:id', requireElevated, async (req, res) => {
  try {
    const docId = Number(req.params.id);
    const doc = await getSql('SELECT id, file_url FROM documents WHERE id = ?', [docId]);
    if (!doc) {
      return res.status(404).json({ ok: false, error: 'Document not found.' });
    }

    const filePath = path.join(uploadsDir, path.basename(doc.file_url));
    fs.unlink(filePath, () => {});

    await runSql('DELETE FROM documents WHERE id = ?', [docId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Notifications ----

app.get('/api/notifications', requireAuth, async (req, res) => {
  try {
    const rows = await allSql(
      'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
      [req.session.user.id]
    );
    const unread = await getSql(
      'SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND read = 0',
      [req.session.user.id]
    );
    res.json({ ok: true, notifications: rows, unreadCount: unread.count });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/notifications/read', requireAuth, async (req, res) => {
  try {
    await runSql('UPDATE notifications SET read = 1 WHERE user_id = ?', [req.session.user.id]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Time Tracking ----

app.get('/api/time', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const role = req.session.user.role;

    let rows;
    if (ROLE_RANK[role] >= ROLE_RANK.admin) {
      rows = await allSql(`
        SELECT t.*, u.name AS userName FROM time_entries t
        LEFT JOIN users u ON u.id = t.user_id
        ORDER BY t.created_at DESC LIMIT 100
      `);
    } else {
      rows = await allSql(
        'SELECT * FROM time_entries WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
        [userId]
      );
    }

    const active = await getSql(
      'SELECT * FROM time_entries WHERE user_id = ? AND clock_out IS NULL ORDER BY id DESC LIMIT 1',
      [userId]
    );

    res.json({ ok: true, entries: rows, active: active || null });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/time/clock-in', requireAuth, async (req, res) => {
  try {
    const { note } = req.body || {};
    const active = await getSql(
      'SELECT id FROM time_entries WHERE user_id = ? AND clock_out IS NULL',
      [req.session.user.id]
    );
    if (active) {
      return res.status(400).json({ ok: false, error: 'You are already clocked in.' });
    }

    const result = await runSql(
      'INSERT INTO time_entries (user_id, clock_in, note) VALUES (?, CURRENT_TIMESTAMP, ?)',
      [req.session.user.id, note || null]
    );

    const entry = await getSql('SELECT * FROM time_entries WHERE id = ?', [result.id]);
    res.json({ ok: true, entry });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/time/clock-out', requireAuth, async (req, res) => {
  try {
    const active = await getSql(
      'SELECT id FROM time_entries WHERE user_id = ? AND clock_out IS NULL ORDER BY id DESC LIMIT 1',
      [req.session.user.id]
    );
    if (!active) {
      return res.status(400).json({ ok: false, error: 'You are not clocked in.' });
    }

    await runSql('UPDATE time_entries SET clock_out = CURRENT_TIMESTAMP WHERE id = ?', [active.id]);
    const entry = await getSql('SELECT * FROM time_entries WHERE id = ?', [active.id]);
    res.json({ ok: true, entry });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Onboarding ----

app.get('/api/onboarding', requireAuth, async (req, res) => {
  try {
    const row = await getSql('SELECT * FROM onboarding WHERE user_id = ?', [req.session.user.id]);
    res.json({ ok: true, onboarding: row || { completed: 0, step: 0 } });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/onboarding', requireAuth, async (req, res) => {
  try {
    const { step, completed } = req.body || {};
    await runSql(
      `INSERT INTO onboarding (user_id, step, completed, updated_at)
       VALUES (?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(user_id) DO UPDATE SET
         step = excluded.step,
         completed = excluded.completed,
         updated_at = CURRENT_TIMESTAMP`,
      [req.session.user.id, step || 0, completed ? 1 : 0]
    );
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Notes / Wiki ----

app.get('/api/notes', requireAuth, async (req, res) => {
  try {
    const { category, wiki } = req.query;
    let sql = 'SELECT * FROM notes';
    const params = [];
    const conditions = [];

    if (category) {
      conditions.push('category = ?');
      params.push(category);
    }
    if (wiki === '1') {
      conditions.push('is_wiki = 1');
    }
    if (conditions.length) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }
    sql += ' ORDER BY updated_at DESC';

    const rows = await allSql(sql, params);
    res.json({ ok: true, notes: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/notes', requireAuth, async (req, res) => {
  try {
    const { title, body, category, isWiki } = req.body || {};
    if (!title || !body) {
      return res.status(400).json({ ok: false, error: 'Title and body are required.' });
    }

    const result = await runSql(
      'INSERT INTO notes (title, body, author_id, author_name, category, is_wiki) VALUES (?, ?, ?, ?, ?, ?)',
      [String(title).trim(), String(body).trim(), req.session.user.id, req.session.user.name || req.session.user.email, category || 'general', isWiki ? 1 : 0]
    );

    const note = await getSql('SELECT * FROM notes WHERE id = ?', [result.id]);
    res.json({ ok: true, note });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/notes/:id', requireAuth, async (req, res) => {
  try {
    const noteId = Number(req.params.id);
    const { title, body, category } = req.body || {};

    const existing = await getSql('SELECT id, author_id FROM notes WHERE id = ?', [noteId]);
    if (!existing) {
      return res.status(404).json({ ok: false, error: 'Note not found.' });
    }

    const role = req.session.user.role;
    if (existing.author_id !== req.session.user.id && ROLE_RANK[role] < ROLE_RANK.admin) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    await runSql(
      'UPDATE notes SET title = ?, body = ?, category = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [title || existing.title, body || existing.body, category || existing.category, noteId]
    );

    const note = await getSql('SELECT * FROM notes WHERE id = ?', [noteId]);
    res.json({ ok: true, note });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/notes/:id', requireAuth, async (req, res) => {
  try {
    const noteId = Number(req.params.id);
    const note = await getSql('SELECT id, author_id FROM notes WHERE id = ?', [noteId]);
    if (!note) {
      return res.status(404).json({ ok: false, error: 'Note not found.' });
    }

    const role = req.session.user.role;
    if (note.author_id !== req.session.user.id && ROLE_RANK[role] < ROLE_RANK.admin) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    await runSql('DELETE FROM notes WHERE id = ?', [noteId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Leave Requests ----

app.get('/api/leave', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const role = req.session.user.role;

    let rows;
    if (ROLE_RANK[role] >= ROLE_RANK.admin) {
      rows = await allSql('SELECT * FROM leave_requests ORDER BY created_at DESC');
    } else {
      rows = await allSql('SELECT * FROM leave_requests WHERE user_id = ? ORDER BY created_at DESC', [userId]);
    }
    res.json({ ok: true, requests: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/leave', requireAuth, async (req, res) => {
  try {
    const { type, startDate, endDate, reason } = req.body || {};
    if (!startDate || !endDate) {
      return res.status(400).json({ ok: false, error: 'Start and end dates are required.' });
    }

    const result = await runSql(
      'INSERT INTO leave_requests (user_id, user_name, type, start_date, end_date, reason) VALUES (?, ?, ?, ?, ?, ?)',
      [req.session.user.id, req.session.user.name || req.session.user.email, type || 'vacation', startDate, endDate, reason || null]
    );

    const request = await getSql('SELECT * FROM leave_requests WHERE id = ?', [result.id]);
    res.json({ ok: true, request });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/leave/:id/status', requireElevated, async (req, res) => {
  try {
    const requestId = Number(req.params.id);
    const { status } = req.body || {};

    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ ok: false, error: 'Invalid status.' });
    }

    const request = await getSql('SELECT id, user_id FROM leave_requests WHERE id = ?', [requestId]);
    if (!request) {
      return res.status(404).json({ ok: false, error: 'Request not found.' });
    }

    await runSql(
      'UPDATE leave_requests SET status = ?, approved_by = ?, approved_by_name = ? WHERE id = ?',
      [status, req.session.user.id, req.session.user.name || req.session.user.email, requestId]
    );

    await createNotification(request.user_id, 'leave', `Fríbeiðni ${status === 'approved' ? 'samþykkt' : 'hafnað'}`, '', '/leave.html');

    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Meeting Notes ----

app.get('/api/meeting-notes', requireAuth, async (req, res) => {
  try {
    const rows = await allSql('SELECT * FROM meeting_notes ORDER BY meeting_date DESC LIMIT 50');
    res.json({ ok: true, notes: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/meeting-notes', requireAuth, async (req, res) => {
  try {
    const { title, body, meetingDate, attendees } = req.body || {};
    if (!title || !body) {
      return res.status(400).json({ ok: false, error: 'Title and body are required.' });
    }

    const result = await runSql(
      'INSERT INTO meeting_notes (title, body, meeting_date, attendees, author_id, author_name) VALUES (?, ?, ?, ?, ?, ?)',
      [String(title).trim(), String(body).trim(), meetingDate || null, attendees || null, req.session.user.id, req.session.user.name || req.session.user.email]
    );

    const note = await getSql('SELECT * FROM meeting_notes WHERE id = ?', [result.id]);
    res.json({ ok: true, note });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/meeting-notes/:id', requireAuth, async (req, res) => {
  try {
    const noteId = Number(req.params.id);
    const note = await getSql('SELECT id, author_id FROM meeting_notes WHERE id = ?', [noteId]);
    if (!note) {
      return res.status(404).json({ ok: false, error: 'Note not found.' });
    }

    const role = req.session.user.role;
    if (note.author_id !== req.session.user.id && ROLE_RANK[role] < ROLE_RANK.admin) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    await runSql('DELETE FROM meeting_notes WHERE id = ?', [noteId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Goals / OKRs ----

app.get('/api/goals', requireAuth, async (req, res) => {
  try {
    const rows = await allSql('SELECT * FROM goals ORDER BY created_at DESC');
    res.json({ ok: true, goals: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/goals', requireAuth, async (req, res) => {
  try {
    const { title, description, targetDate } = req.body || {};
    if (!title) {
      return res.status(400).json({ ok: false, error: 'Title is required.' });
    }

    const result = await runSql(
      'INSERT INTO goals (title, description, owner_id, owner_name, target_date) VALUES (?, ?, ?, ?, ?)',
      [String(title).trim(), description || null, req.session.user.id, req.session.user.name || req.session.user.email, targetDate || null]
    );

    const goal = await getSql('SELECT * FROM goals WHERE id = ?', [result.id]);
    res.json({ ok: true, goal });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/goals/:id', requireAuth, async (req, res) => {
  try {
    const goalId = Number(req.params.id);
    const { title, description, progress, status, targetDate } = req.body || {};

    const existing = await getSql('SELECT id, owner_id FROM goals WHERE id = ?', [goalId]);
    if (!existing) {
      return res.status(404).json({ ok: false, error: 'Goal not found.' });
    }

    const role = req.session.user.role;
    if (existing.owner_id !== req.session.user.id && ROLE_RANK[role] < ROLE_RANK.admin) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    await runSql(
      'UPDATE goals SET title = ?, description = ?, progress = ?, status = ?, target_date = ? WHERE id = ?',
      [title || existing.title, description !== undefined ? description : null, progress !== undefined ? progress : existing.progress, status || existing.status, targetDate !== undefined ? targetDate : null, goalId]
    );

    const goal = await getSql('SELECT * FROM goals WHERE id = ?', [goalId]);
    res.json({ ok: true, goal });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/goals/:id', requireAuth, async (req, res) => {
  try {
    const goalId = Number(req.params.id);
    const goal = await getSql('SELECT id, owner_id FROM goals WHERE id = ?', [goalId]);
    if (!goal) {
      return res.status(404).json({ ok: false, error: 'Goal not found.' });
    }

    const role = req.session.user.role;
    if (goal.owner_id !== req.session.user.id && ROLE_RANK[role] < ROLE_RANK.admin) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }

    await runSql('DELETE FROM goals WHERE id = ?', [goalId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Training Courses ----

app.get('/api/courses', requireAuth, async (req, res) => {
  try {
    const rows = await allSql('SELECT * FROM courses ORDER BY created_at DESC');
    const userId = req.session.user.id;

    const enriched = await Promise.all(rows.map(async (course) => {
      const progress = await getSql('SELECT progress, completed FROM course_progress WHERE user_id = ? AND course_id = ?', [userId, course.id]);
      return { ...course, progress: progress ? progress.progress : 0, completed: progress ? progress.completed : 0 };
    }));

    res.json({ ok: true, courses: enriched });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/courses', requireElevated, async (req, res) => {
  try {
    const { title, description, content, durationMinutes } = req.body || {};
    if (!title) {
      return res.status(400).json({ ok: false, error: 'Title is required.' });
    }

    const result = await runSql(
      'INSERT INTO courses (title, description, content, duration_minutes, created_by) VALUES (?, ?, ?, ?, ?)',
      [String(title).trim(), description || null, content || null, durationMinutes || null, req.session.user.id]
    );

    const course = await getSql('SELECT * FROM courses WHERE id = ?', [result.id]);
    res.json({ ok: true, course });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/courses/:id/progress', requireAuth, async (req, res) => {
  try {
    const courseId = Number(req.params.id);
    const { progress, completed } = req.body || {};

    await runSql(
      `INSERT INTO course_progress (user_id, course_id, progress, completed, updated_at)
       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(user_id, course_id) DO UPDATE SET
         progress = excluded.progress,
         completed = excluded.completed,
         updated_at = CURRENT_TIMESTAMP`,
      [req.session.user.id, courseId, progress || 0, completed ? 1 : 0]
    );

    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- 2FA ----

app.get('/api/2fa/status', requireAuth, async (req, res) => {
  try {
    const row = await getSql('SELECT enabled FROM user_2fa WHERE user_id = ?', [req.session.user.id]);
    res.json({ ok: true, enabled: row ? row.enabled === 1 : false });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/2fa/setup', requireAuth, async (req, res) => {
  try {
    const secret = base32Encode(crypto.randomBytes(20));
    const backupCodes = Array.from({ length: 8 }, () => crypto.randomBytes(4).toString('hex'));
    const account = encodeURIComponent(req.session.user.email || 'avara');
    const otpauthUrl = `otpauth://totp/Avara:${account}?secret=${secret}&issuer=Avara&algorithm=SHA1&digits=6&period=30`;

    await runSql(
      `INSERT INTO user_2fa (user_id, secret, enabled, backup_codes) VALUES (?, ?, 0, ?)
       ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret, backup_codes = excluded.backup_codes`,
      [req.session.user.id, secret, JSON.stringify(backupCodes)]
    );

    res.json({ ok: true, secret, backupCodes, otpauthUrl });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/2fa/enable', requireAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    if (!code) {
      return res.status(400).json({ ok: false, error: 'Verification code is required.' });
    }

    const row = await getSql('SELECT secret FROM user_2fa WHERE user_id = ?', [req.session.user.id]);
    if (!row) {
      return res.status(400).json({ ok: false, error: 'Run 2FA setup first.' });
    }

    if (!verifyTotp(row.secret, code)) {
      return res.status(400).json({ ok: false, error: 'Invalid verification code.' });
    }

    await runSql('UPDATE user_2fa SET enabled = 1 WHERE user_id = ?', [req.session.user.id]);
    await logAudit(req.session.user.name || req.session.user.email, '2fa_enable', 'Two-factor authentication enabled');
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/2fa/disable', requireAuth, async (req, res) => {
  try {
    const { code } = req.body || {};
    const row = await getSql('SELECT secret, backup_codes FROM user_2fa WHERE user_id = ?', [req.session.user.id]);
    if (!row) {
      return res.json({ ok: true });
    }

    // Require a valid TOTP or backup code to disable
    let verified = code ? verifyTotp(row.secret, code) : false;
    if (!verified && code) {
      try {
        verified = JSON.parse(row.backup_codes || '[]').includes(String(code).trim().toLowerCase());
      } catch (e) { verified = false; }
    }
    if (!verified) {
      return res.status(400).json({ ok: false, error: 'A valid verification code is required to disable 2FA.' });
    }

    await runSql('UPDATE user_2fa SET enabled = 0 WHERE user_id = ?', [req.session.user.id]);
    await logAudit(req.session.user.name || req.session.user.email, '2fa_disable', 'Two-factor authentication disabled');
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Custom Fields ----

app.get('/api/custom-fields', requireAuth, async (req, res) => {
  try {
    const { entityType } = req.query;
    let sql = 'SELECT * FROM custom_fields';
    const params = [];
    if (entityType) {
      sql += ' WHERE entity_type = ?';
      params.push(entityType);
    }
    sql += ' ORDER BY created_at ASC';
    const rows = await allSql(sql, params);
    res.json({ ok: true, fields: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/custom-fields', requireElevated, async (req, res) => {
  try {
    const { entityType, fieldName, fieldType, fieldLabel, required } = req.body || {};
    if (!entityType || !fieldName || !fieldLabel) {
      return res.status(400).json({ ok: false, error: 'Entity type, field name, and label are required.' });
    }

    const result = await runSql(
      'INSERT INTO custom_fields (entity_type, field_name, field_type, field_label, required) VALUES (?, ?, ?, ?, ?)',
      [entityType, fieldName, fieldType || 'text', fieldLabel, required ? 1 : 0]
    );

    const field = await getSql('SELECT * FROM custom_fields WHERE id = ?', [result.id]);
    res.json({ ok: true, field });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Org Chart ----

app.get('/api/org-chart', requireAuth, async (req, res) => {
  try {
    const rows = await allSql('SELECT id, name, email, role, department, avatar_color, avatar_url FROM users WHERE active = 1 ORDER BY department, name');
    res.json({ ok: true, users: rows.map(publicUser) });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Custom Field Values ----

app.get('/api/custom-field-values', requireAuth, async (req, res) => {
  try {
    const { entityType, entityId } = req.query;
    if (!entityType || !entityId) {
      return res.status(400).json({ ok: false, error: 'entityType and entityId are required.' });
    }
    const rows = await allSql(
      'SELECT field_id AS fieldId, value FROM custom_field_values WHERE entity_type = ? AND entity_id = ?',
      [entityType, Number(entityId)]
    );
    res.json({ ok: true, values: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/custom-field-values', requireAuth, async (req, res) => {
  try {
    const { entityType, entityId, values } = req.body || {};
    if (!entityType || !entityId || typeof values !== 'object' || values === null) {
      return res.status(400).json({ ok: false, error: 'entityType, entityId and values object are required.' });
    }
    for (const [fieldId, value] of Object.entries(values)) {
      await runSql(
        `INSERT INTO custom_field_values (field_id, entity_type, entity_id, value)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(field_id, entity_type, entity_id) DO UPDATE SET value = excluded.value`,
        [Number(fieldId), entityType, Number(entityId), value === null || value === undefined ? null : String(value)]
      );
    }
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Leave Balances ----

async function ensureLeaveBalance(userId, year) {
  const existing = await getSql('SELECT * FROM leave_balances WHERE user_id = ? AND year = ?', [userId, year]);
  if (existing) return existing;
  await runSql('INSERT OR IGNORE INTO leave_balances (user_id, year, allowance, used) VALUES (?, ?, 25, 0)', [userId, year]);
  return getSql('SELECT * FROM leave_balances WHERE user_id = ? AND year = ?', [userId, year]);
}

app.get('/api/leave/balance', requireAuth, async (req, res) => {
  try {
    const year = Number(req.query.year) || new Date().getFullYear();
    const isElevated = ROLE_RANK[req.session.user.role] >= ROLE_RANK.admin;
    const targetId = req.query.userId && isElevated ? Number(req.query.userId) : req.session.user.id;
    const balance = await ensureLeaveBalance(targetId, year);
    res.json({ ok: true, balance });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/admin/leave-balances', requireElevated, async (req, res) => {
  try {
    const year = Number(req.query.year) || new Date().getFullYear();
    const rows = await allSql(
      `SELECT u.id AS userId, u.name, u.email, u.department,
              COALESCE(b.allowance, 25) AS allowance, COALESCE(b.used, 0) AS used
       FROM users u LEFT JOIN leave_balances b ON b.user_id = u.id AND b.year = ?
       WHERE u.active = 1 ORDER BY u.name`,
      [year]
    );
    res.json({ ok: true, balances: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/admin/leave-balance', requireElevated, async (req, res) => {
  try {
    const { userId, year, allowance } = req.body || {};
    if (!userId || !year || allowance === undefined) {
      return res.status(400).json({ ok: false, error: 'userId, year and allowance are required.' });
    }
    await ensureLeaveBalance(Number(userId), Number(year));
    await runSql('UPDATE leave_balances SET allowance = ? WHERE user_id = ? AND year = ?', [Number(allowance), Number(userId), Number(year)]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Expenses ----

app.get('/api/expenses', requireAuth, async (req, res) => {
  try {
    const isElevated = ROLE_RANK[req.session.user.role] >= ROLE_RANK.admin;
    const rows = isElevated
      ? await allSql('SELECT * FROM expenses ORDER BY created_at DESC')
      : await allSql('SELECT * FROM expenses WHERE user_id = ? ORDER BY created_at DESC', [req.session.user.id]);
    res.json({ ok: true, expenses: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/expenses', requireAuth, (req, res) => {
  fileUpload.single('receipt')(req, res, async (uploadError) => {
    if (uploadError) {
      return res.status(400).json({ ok: false, error: uploadError.message || 'Unable to upload receipt.' });
    }
    try {
      const { title, category, amount, currency, expenseDate, note } = req.body || {};
      if (!title || amount === undefined || Number.isNaN(Number(amount))) {
        return res.status(400).json({ ok: false, error: 'Title and a valid amount are required.' });
      }
      const receiptUrl = req.file ? `/uploads/${req.file.filename}` : null;
      const result = await runSql(
        `INSERT INTO expenses (user_id, user_name, title, category, amount, currency, expense_date, receipt_url, receipt_name, note)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          req.session.user.id,
          req.session.user.name || req.session.user.email,
          String(title).trim(),
          category || 'other',
          Number(amount),
          currency || 'ISK',
          expenseDate || isoDate(new Date()),
          receiptUrl,
          req.file ? req.file.originalname : null,
          note || null
        ]
      );
      const expense = await getSql('SELECT * FROM expenses WHERE id = ?', [result.id]);

      const admins = await allSql("SELECT id FROM users WHERE role IN ('admin', 'owner') AND active = 1 AND id != ?", [req.session.user.id]);
      for (const admin of admins) {
        await createNotification(admin.id, 'expense', 'Nýr kostnaðaruppgjör', `${String(title).trim()} — ${Number(amount)} ${currency || 'ISK'}`, '/Expenses.html');
      }

      res.json({ ok: true, expense });
    } catch (error) {
      res.status(500).json({ ok: false, error: error.message });
    }
  });
});

app.put('/api/expenses/:id/status', requireElevated, async (req, res) => {
  try {
    const expenseId = Number(req.params.id);
    const { status } = req.body || {};
    if (!['pending', 'approved', 'rejected'].includes(status)) {
      return res.status(400).json({ ok: false, error: 'Invalid status.' });
    }
    const expense = await getSql('SELECT id, user_id, title FROM expenses WHERE id = ?', [expenseId]);
    if (!expense) {
      return res.status(404).json({ ok: false, error: 'Expense not found.' });
    }
    await runSql(
      'UPDATE expenses SET status = ?, reviewed_by = ?, reviewed_by_name = ? WHERE id = ?',
      [status, req.session.user.id, req.session.user.name || req.session.user.email, expenseId]
    );
    await createNotification(expense.user_id, 'expense', `Kostnaðaruppgjör ${status === 'approved' ? 'samþykkt' : 'hafnað'}`, expense.title, '/Expenses.html');
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/expenses/:id', requireAuth, async (req, res) => {
  try {
    const expenseId = Number(req.params.id);
    const expense = await getSql('SELECT id, user_id, status FROM expenses WHERE id = ?', [expenseId]);
    if (!expense) {
      return res.status(404).json({ ok: false, error: 'Expense not found.' });
    }
    const isElevated = ROLE_RANK[req.session.user.role] >= ROLE_RANK.admin;
    if (expense.user_id !== req.session.user.id && !isElevated) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }
    if (expense.status !== 'pending' && !isElevated) {
      return res.status(400).json({ ok: false, error: 'Only pending expenses can be deleted.' });
    }
    await runSql('DELETE FROM expenses WHERE id = ?', [expenseId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Performance Reviews ----

app.get('/api/reviews', requireAuth, async (req, res) => {
  try {
    const isElevated = ROLE_RANK[req.session.user.role] >= ROLE_RANK.admin;
    const userId = req.session.user.id;
    const rows = isElevated
      ? await allSql('SELECT * FROM reviews ORDER BY created_at DESC')
      : await allSql('SELECT * FROM reviews WHERE subject_id = ? OR reviewer_id = ? ORDER BY created_at DESC', [userId, userId]);
    res.json({ ok: true, reviews: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/reviews', requireElevated, async (req, res) => {
  try {
    const { cycle, subjectId, reviewerId, type } = req.body || {};
    if (!cycle || !subjectId) {
      return res.status(400).json({ ok: false, error: 'Cycle and subject are required.' });
    }
    const subject = await getSql('SELECT id, name, email FROM users WHERE id = ?', [Number(subjectId)]);
    if (!subject) {
      return res.status(404).json({ ok: false, error: 'Subject user not found.' });
    }
    let reviewerName = null;
    if (reviewerId) {
      const reviewer = await getSql('SELECT id, name, email FROM users WHERE id = ?', [Number(reviewerId)]);
      reviewerName = reviewer ? (reviewer.name || reviewer.email) : null;
    }
    const reviewType = type === 'manager' ? 'manager' : 'self';
    const result = await runSql(
      `INSERT INTO reviews (cycle, subject_id, subject_name, reviewer_id, reviewer_name, type)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [String(cycle).trim(), subject.id, subject.name || subject.email, reviewerId || null, reviewerName, reviewType]
    );
    const review = await getSql('SELECT * FROM reviews WHERE id = ?', [result.id]);
    const targetUserId = reviewType === 'self' ? subject.id : Number(reviewerId);
    if (targetUserId) {
      await createNotification(targetUserId, 'review', 'Ný umsögn í vinnu', `Umsagnarhrina: ${cycle}`, '/Reviews.html');
    }
    res.json({ ok: true, review });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/reviews/:id', requireAuth, async (req, res) => {
  try {
    const reviewId = Number(req.params.id);
    const { rating, feedback } = req.body || {};
    const review = await getSql('SELECT * FROM reviews WHERE id = ?', [reviewId]);
    if (!review) {
      return res.status(404).json({ ok: false, error: 'Review not found.' });
    }
    const userId = req.session.user.id;
    const isParticipant = review.subject_id === userId || review.reviewer_id === userId;
    const isElevated = ROLE_RANK[req.session.user.role] >= ROLE_RANK.admin;
    if (!isParticipant && !isElevated) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }
    const ratingNum = rating !== undefined ? Math.max(1, Math.min(5, Number(rating) || 0)) : review.rating;
    await runSql(
      'UPDATE reviews SET rating = ?, feedback = ?, status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
      [ratingNum, feedback !== undefined ? String(feedback) : review.feedback, 'submitted', reviewId]
    );
    const updated = await getSql('SELECT * FROM reviews WHERE id = ?', [reviewId]);
    res.json({ ok: true, review: updated });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/reviews/:id', requireElevated, async (req, res) => {
  try {
    await runSql('DELETE FROM reviews WHERE id = ?', [Number(req.params.id)]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Surveys / Pulse ----

app.get('/api/surveys', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    const surveys = await allSql('SELECT * FROM surveys ORDER BY created_at DESC');
    const enriched = await Promise.all(surveys.map(async (survey) => {
      const mine = await getSql('SELECT id, rating FROM survey_responses WHERE survey_id = ? AND user_id = ?', [survey.id, userId]);
      const count = await getSql('SELECT COUNT(*) AS count FROM survey_responses WHERE survey_id = ?', [survey.id]);
      const avg = await getSql('SELECT AVG(rating) AS avg FROM survey_responses WHERE survey_id = ? AND rating IS NOT NULL', [survey.id]);
      return { ...survey, responded: !!mine, myRating: mine ? mine.rating : null, responses: count.count, average: avg.avg };
    }));
    res.json({ ok: true, surveys: enriched });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/surveys', requireElevated, async (req, res) => {
  try {
    const { title, question, anonymous } = req.body || {};
    if (!title || !question) {
      return res.status(400).json({ ok: false, error: 'Title and question are required.' });
    }
    const result = await runSql(
      'INSERT INTO surveys (title, question, anonymous, created_by) VALUES (?, ?, ?, ?)',
      [String(title).trim(), String(question).trim(), anonymous === false ? 0 : 1, req.session.user.id]
    );
    const survey = await getSql('SELECT * FROM surveys WHERE id = ?', [result.id]);

    const users = await allSql('SELECT id FROM users WHERE active = 1 AND id != ?', [req.session.user.id]);
    for (const user of users) {
      await createNotification(user.id, 'survey', 'Ný könnun', String(title).trim(), '/Surveys.html');
    }

    res.json({ ok: true, survey });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/surveys/:id/respond', requireAuth, async (req, res) => {
  try {
    const surveyId = Number(req.params.id);
    const { rating, answer } = req.body || {};
    const survey = await getSql('SELECT * FROM surveys WHERE id = ? AND active = 1', [surveyId]);
    if (!survey) {
      return res.status(404).json({ ok: false, error: 'Survey not found or closed.' });
    }
    const existing = await getSql('SELECT id FROM survey_responses WHERE survey_id = ? AND user_id = ?', [surveyId, req.session.user.id]);
    if (existing) {
      await runSql('UPDATE survey_responses SET rating = ?, answer = ?, created_at = CURRENT_TIMESTAMP WHERE id = ?', [rating || null, answer || null, existing.id]);
    } else {
      await runSql(
        'INSERT INTO survey_responses (survey_id, user_id, rating, answer) VALUES (?, ?, ?, ?)',
        [surveyId, req.session.user.id, rating || null, answer || null]
      );
    }
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/surveys/:id/results', requireElevated, async (req, res) => {
  try {
    const surveyId = Number(req.params.id);
    const survey = await getSql('SELECT * FROM surveys WHERE id = ?', [surveyId]);
    if (!survey) {
      return res.status(404).json({ ok: false, error: 'Survey not found.' });
    }
    const stats = await getSql(
      'SELECT COUNT(*) AS count, AVG(rating) AS avg FROM survey_responses WHERE survey_id = ?',
      [surveyId]
    );
    const distribution = await allSql(
      'SELECT rating, COUNT(*) AS count FROM survey_responses WHERE survey_id = ? AND rating IS NOT NULL GROUP BY rating ORDER BY rating',
      [surveyId]
    );
    const comments = await allSql(
      `SELECT r.answer, r.created_at AS createdAt, ${survey.anonymous ? 'NULL' : 'u.name'} AS author
       FROM survey_responses r LEFT JOIN users u ON u.id = r.user_id
       WHERE r.survey_id = ? AND r.answer IS NOT NULL AND r.answer != '' ORDER BY r.created_at DESC`,
      [surveyId]
    );
    res.json({ ok: true, survey, stats, distribution, comments });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/surveys/:id/toggle', requireElevated, async (req, res) => {
  try {
    const surveyId = Number(req.params.id);
    await runSql('UPDATE surveys SET active = 1 - active WHERE id = ?', [surveyId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/surveys/:id', requireElevated, async (req, res) => {
  try {
    const surveyId = Number(req.params.id);
    await runSql('DELETE FROM survey_responses WHERE survey_id = ?', [surveyId]);
    await runSql('DELETE FROM surveys WHERE id = ?', [surveyId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Recruiting: Jobs & Applicants ----

const APPLICANT_STAGES = ['applied', 'screening', 'interview', 'offer', 'hired', 'rejected'];

app.get('/api/jobs', requireAuth, async (req, res) => {
  try {
    const jobs = await allSql('SELECT * FROM jobs ORDER BY created_at DESC');
    const enriched = await Promise.all(jobs.map(async (job) => {
      const count = await getSql('SELECT COUNT(*) AS count FROM applicants WHERE job_id = ?', [job.id]);
      return { ...job, applicantCount: count.count };
    }));
    res.json({ ok: true, jobs: enriched });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/jobs', requireElevated, async (req, res) => {
  try {
    const { title, department, description } = req.body || {};
    if (!title) {
      return res.status(400).json({ ok: false, error: 'Title is required.' });
    }
    const result = await runSql(
      'INSERT INTO jobs (title, department, description, created_by) VALUES (?, ?, ?, ?)',
      [String(title).trim(), department || null, description || null, req.session.user.id]
    );
    const job = await getSql('SELECT * FROM jobs WHERE id = ?', [result.id]);
    res.json({ ok: true, job });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/jobs/:id', requireElevated, async (req, res) => {
  try {
    const jobId = Number(req.params.id);
    const { status } = req.body || {};
    if (!['open', 'closed', 'on-hold'].includes(status)) {
      return res.status(400).json({ ok: false, error: 'Invalid status.' });
    }
    await runSql('UPDATE jobs SET status = ? WHERE id = ?', [status, jobId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/jobs/:id', requireElevated, async (req, res) => {
  try {
    const jobId = Number(req.params.id);
    await runSql('DELETE FROM applicants WHERE job_id = ?', [jobId]);
    await runSql('DELETE FROM jobs WHERE id = ?', [jobId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/jobs/:id/applicants', requireElevated, async (req, res) => {
  try {
    const rows = await allSql('SELECT * FROM applicants WHERE job_id = ? ORDER BY created_at DESC', [Number(req.params.id)]);
    res.json({ ok: true, applicants: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/jobs/:id/applicants', requireElevated, async (req, res) => {
  try {
    const jobId = Number(req.params.id);
    const { name, email, phone, note } = req.body || {};
    if (!name) {
      return res.status(400).json({ ok: false, error: 'Name is required.' });
    }
    const job = await getSql('SELECT id FROM jobs WHERE id = ?', [jobId]);
    if (!job) {
      return res.status(404).json({ ok: false, error: 'Job not found.' });
    }
    const result = await runSql(
      'INSERT INTO applicants (job_id, name, email, phone, note) VALUES (?, ?, ?, ?, ?)',
      [jobId, String(name).trim(), email || null, phone || null, note || null]
    );
    const applicant = await getSql('SELECT * FROM applicants WHERE id = ?', [result.id]);
    res.json({ ok: true, applicant });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.put('/api/applicants/:id/stage', requireElevated, async (req, res) => {
  try {
    const applicantId = Number(req.params.id);
    const { stage } = req.body || {};
    if (!APPLICANT_STAGES.includes(stage)) {
      return res.status(400).json({ ok: false, error: 'Invalid stage.' });
    }
    await runSql('UPDATE applicants SET stage = ? WHERE id = ?', [stage, applicantId]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/applicants/:id', requireElevated, async (req, res) => {
  try {
    await runSql('DELETE FROM applicants WHERE id = ?', [Number(req.params.id)]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Shifts / Roster ----

app.get('/api/shifts', requireAuth, async (req, res) => {
  try {
    const { from, to } = req.query;
    let sql = `SELECT s.*, u.name AS userName FROM shifts s LEFT JOIN users u ON u.id = s.user_id`;
    const params = [];
    const conditions = [];
    if (from) { conditions.push('s.shift_date >= ?'); params.push(from); }
    if (to) { conditions.push('s.shift_date <= ?'); params.push(to); }
    if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
    sql += ' ORDER BY s.shift_date, s.start_time';
    const rows = await allSql(sql, params);
    res.json({ ok: true, shifts: rows });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.post('/api/shifts', requireElevated, async (req, res) => {
  try {
    const { userId, shiftDate, startTime, endTime, note } = req.body || {};
    if (!userId || !shiftDate) {
      return res.status(400).json({ ok: false, error: 'userId and shiftDate are required.' });
    }
    const user = await getSql('SELECT id FROM users WHERE id = ?', [Number(userId)]);
    if (!user) {
      return res.status(404).json({ ok: false, error: 'User not found.' });
    }
    const result = await runSql(
      'INSERT INTO shifts (user_id, shift_date, start_time, end_time, note, created_by) VALUES (?, ?, ?, ?, ?, ?)',
      [Number(userId), shiftDate, startTime || null, endTime || null, note || null, req.session.user.id]
    );
    const shift = await getSql('SELECT * FROM shifts WHERE id = ?', [result.id]);
    await createNotification(Number(userId), 'shift', 'Ný vakt skráð', `${shiftDate}${startTime ? ' ' + startTime : ''}${endTime ? '–' + endTime : ''}`, '/Roster.html');
    res.json({ ok: true, shift });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.delete('/api/shifts/:id', requireElevated, async (req, res) => {
  try {
    await runSql('DELETE FROM shifts WHERE id = ?', [Number(req.params.id)]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Timesheet Reports ----

app.get('/api/time/report', requireAuth, async (req, res) => {
  try {
    const isElevated = ROLE_RANK[req.session.user.role] >= ROLE_RANK.admin;
    if (!isElevated) {
      return res.status(403).json({ ok: false, error: 'Forbidden' });
    }
    const { from, to } = req.query;
    let sql = `SELECT t.*, u.name AS userName, u.department FROM time_entries t LEFT JOIN users u ON u.id = t.user_id WHERE t.clock_out IS NOT NULL`;
    const params = [];
    if (from) { sql += ' AND date(t.clock_in) >= ?'; params.push(from); }
    if (to) { sql += ' AND date(t.clock_in) <= ?'; params.push(to); }
    sql += ' ORDER BY t.clock_in DESC LIMIT 2000';
    const rows = await allSql(sql, params);

    const entries = rows.map((row) => {
      const hours = (new Date(row.clock_out) - new Date(row.clock_in)) / 3600000;
      return { ...row, hours: Math.round(hours * 100) / 100 };
    });

    // Per-user weekly totals with overtime flag (>40h)
    const byUserWeek = {};
    for (const entry of entries) {
      const d = new Date(entry.clock_in);
      const weekStart = new Date(d);
      weekStart.setDate(d.getDate() - ((d.getDay() + 6) % 7)); // Monday
      const key = `${entry.user_id}|${isoDate(weekStart)}`;
      if (!byUserWeek[key]) {
        byUserWeek[key] = { userId: entry.user_id, userName: entry.userName, weekStart: isoDate(weekStart), hours: 0 };
      }
      byUserWeek[key].hours += entry.hours;
    }
    const weekly = Object.values(byUserWeek).map((w) => ({ ...w, hours: Math.round(w.hours * 100) / 100, overtime: w.hours > 40 }));
    weekly.sort((a, b) => (a.userName || '').localeCompare(b.userName || '') || b.weekStart.localeCompare(a.weekStart));

    res.json({ ok: true, entries, weekly });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

app.get('/api/time/report.csv', requireElevated, async (req, res) => {
  try {
    const { from, to } = req.query;
    let sql = `SELECT t.*, u.name AS userName FROM time_entries t LEFT JOIN users u ON u.id = t.user_id WHERE t.clock_out IS NOT NULL`;
    const params = [];
    if (from) { sql += ' AND date(t.clock_in) >= ?'; params.push(from); }
    if (to) { sql += ' AND date(t.clock_in) <= ?'; params.push(to); }
    sql += ' ORDER BY t.clock_in DESC LIMIT 5000';
    const rows = await allSql(sql, params);
    const csv = toCsv(rows, [
      { key: 'userName', label: 'Employee' },
      { key: 'clock_in', label: 'Clock In' },
      { key: 'clock_out', label: 'Clock Out' },
      { key: 'note', label: 'Note' },
      {
        key: 'hours', label: 'Hours',
        format: (row) => Math.round(((new Date(row.clock_out) - new Date(row.clock_in)) / 3600000) * 100) / 100
      }
    ]);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="timesheet-report.csv"');
    res.send(csv);
  } catch (error) {
    res.status(500).json({ ok: false, error: error.message });
  }
});

// ---- Friendly employee-only login path ----
app.get(['/innskra', '/innskrá'], (req, res) => {
  res.sendFile(path.join(rootDir, 'Login.html'));
});

app.get('/reset-password', (req, res) => {
  res.sendFile(path.join(rootDir, 'ResetPassword.html'));
});

app.use('/api', (req, res) => {
  return res.status(404).json({ ok: false, error: 'API-slóð fannst ekki.' });
});

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) {
    return next();
  }

  const requestedFile = req.path === '/' ? 'Home.html' : req.path.replace(/^\//, '');
  const allowedPages = ['Home.html', 'Login.html', 'Signup.html', 'admin.html', 'chat.html', 'Employee.html', 'Profiles.html', 'Dashboard.html', 'Profile.html', 'Tasks.html', 'Announcements.html', 'Calendar.html', 'Documents.html', 'ResetPassword.html', '404.html', 'Notes.html', 'Leave.html', 'Goals.html', 'Courses.html', 'OrgChart.html', 'Settings.html'];

  if (requestedFile && allowedPages.includes(requestedFile)) {
    return res.sendFile(path.join(rootDir, requestedFile));
  }

  return res.sendFile(path.join(rootDir, 'Home.html'));
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (!req.path.startsWith('/api/')) return next(error);

  const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600
    ? error.status
    : 500;
  if (status === 400) {
    console.warn('Invalid API request:', error.message);
  } else {
    console.error('API request failed:', error.message);
  }

  return res.status(status).json({
    ok: false,
    error: status === 400 ? 'Ógilt beiðnisnið.' : 'Villa kom upp á netþjóninum.'
  });
});

async function startServer() {
  await initDatabase();
  server.listen(PORT, () => {
    console.log(`Avara server running at http://localhost:${PORT}`);
  });
}

startServer().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});