// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// const mysql = require('mysql2/promise');
const { Pool } = require('pg');
const path = require('path');
const app = express();
app.use(cors());
app.use(express.json());

// const pool = mysql.createPool({
//   host: process.env.DB_HOST || '127.0.0.1',
//   port: +process.env.DB_PORT || 3306,
//   user: process.env.DB_USER || 'root',
//   password: process.env.DB_PASS || '',
//   database: process.env.DB_NAME || 'studyhub',
//   waitForConnections: true,
//   connectionLimit: 10,
//   queueLimit: 0
// });


const pool = new Pool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: +process.env.DB_PORT || 5432,
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'studyhub',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});


// Serve static files from frontend folder
app.use(express.static(path.join(__dirname, 'frontend')));

// Main route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Serve static files from frontend folder and root
app.use(express.static('frontend'));
app.use(express.static('.'));

// Serve index.html for root route
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

// helper
function makeToken(user) {
  return jwt.sign({ id: user.id, email: user.email, display_name: user.display_name }, JWT_SECRET, { expiresIn: '7d' });
}

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/* ========== AUTH ========== */
// register
app.post('/api/register', async (req, res) => {
  const { email, password, display_name } = req.body;
  if (!email || !password || !display_name) return res.status(400).json({ error: 'Missing fields' });
  const conn = await pool.getConnection();
  try {
    const [exist] = await conn.query('SELECT id FROM users WHERE email = ?', [email]);
    if (exist.length) return res.status(400).json({ error: 'Email in use' });
    const hash = await bcrypt.hash(password, 10);
    const [r] = await conn.query('INSERT INTO users (email, password_hash, display_name) VALUES (?,?,?)', [email, hash, display_name]);
    const user = { id: r.insertId, email, display_name };
    const token = makeToken(user);
    res.json({ token, user });
  } finally {
    conn.release();
  }
});

// login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query('SELECT id, email, password_hash, display_name FROM users WHERE email = ?', [email]);
    if (!rows.length) return res.status(400).json({ error: 'Invalid credentials' });
    const u = rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    const token = makeToken(u);
    res.json({ token, user: { id: u.id, email: u.email, display_name: u.display_name } });
  } finally {
    conn.release();
  }
});

/* ========== PROFILE & SUBJECTS ========== */

// set profile
app.post('/api/profile', authMiddleware, async (req, res) => {
  const { bio, location, availability } = req.body;
  const conn = await pool.getConnection();
  try {
    await conn.query(
      `INSERT INTO profiles (user_id, bio, location, availability) VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE bio=VALUES(bio), location=VALUES(location), availability=VALUES(availability)`,
      [req.user.id, bio||null, location||null, availability||null]
    );
    res.json({ ok: true });
  } finally { conn.release(); }
});

// add/update user subject+level
app.post('/api/user/subject', authMiddleware, async (req, res) => {
  const { subject_id, level } = req.body;
  if (!subject_id || !level) return res.status(400).json({ error: 'Missing' });
  const conn = await pool.getConnection();
  try {
    await conn.query(
      `INSERT INTO user_subjects (user_id, subject_id, level) VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE level=VALUES(level)`,
      [req.user.id, subject_id, level]
    );
    res.json({ ok: true });
  } finally { conn.release(); }
});

// list subjects
app.get('/api/subjects', async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query('SELECT * FROM subjects ORDER BY name');
    res.json(rows);
  } finally { conn.release(); }
});

/* ========== GROUPS & MATCHING ========== */

// create group
app.post('/api/groups', authMiddleware, async (req, res) => {
  const { title, subject_id, description, level, max_members } = req.body;
  const conn = await pool.getConnection();
  try {
    const [r] = await conn.query(
      `INSERT INTO groups (title, subject_id, description, owner_id, level, max_members)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [title, subject_id, description||'', req.user.id, level||'mixed', max_members||10]
    );
    const groupId = r.insertId;
    await conn.query('INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, ?)', [groupId, req.user.id, 'owner']);
    res.json({ ok: true, groupId });
  } finally { conn.release(); }
});

// join group
app.post('/api/groups/:id/join', authMiddleware, async (req, res) => {
  const groupId = +req.params.id;
  const conn = await pool.getConnection();
  try {
    const [gRows] = await conn.query('SELECT max_members FROM groups WHERE id = ?', [groupId]);
    if (!gRows.length) return res.status(404).json({ error: 'Group not found' });
    const g = gRows[0];
    const [countRows] = await conn.query('SELECT COUNT(*) as cnt FROM group_members WHERE group_id = ?', [groupId]);
    const memberCount = countRows[0].cnt || 0;
    const [exists] = await conn.query('SELECT * FROM group_members WHERE group_id = ? AND user_id = ?', [groupId, req.user.id]);
    if (exists.length) return res.status(400).json({ error: 'Already a member' });
    if (memberCount >= g.max_members) return res.status(400).json({ error: 'Group full' });
    await conn.query('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [groupId, req.user.id]);
    res.json({ ok: true });
  } finally { conn.release(); }
});

// search for matching users or groups: match by subject + level
app.get('/api/match', authMiddleware, async (req, res) => {
  const { subject_id, level, type } = req.query;
  const conn = await pool.getConnection();
  try {
    if (type === 'group') {
      const [rows] = await conn.query(
        `SELECT g.*, s.name AS subject_name, u.display_name as owner_name,
           (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count
         FROM groups g
         JOIN subjects s ON s.id = g.subject_id
         JOIN users u ON u.id = g.owner_id
         WHERE g.subject_id = ? ${level ? 'AND (g.level = ? OR g.level = "mixed")' : '' }
         ORDER BY g.created_at DESC
         LIMIT 50`,
        level ? [subject_id, level] : [subject_id]
      );
      return res.json(rows);
    } else {
      const [rows] = await conn.query(
        `SELECT u.id, u.display_name, p.bio, us.level, s.name as subject_name
         FROM user_subjects us
         JOIN users u ON u.id = us.user_id
         LEFT JOIN profiles p ON p.user_id = u.id
         JOIN subjects s ON s.id = us.subject_id
         WHERE us.subject_id = ? ${level ? 'AND us.level = ?' : ''}
         LIMIT 50`,
         level ? [subject_id, level] : [subject_id]
      );
      return res.json(rows);
    }
  } finally { conn.release(); }
});

// get group messages (simple)
app.get('/api/groups/:id/messages', authMiddleware, async (req, res) => {
  const groupId = +req.params.id;
  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.query(
      `SELECT gm.*, u.display_name FROM group_messages gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = ? ORDER BY gm.sent_at ASC LIMIT 200`,
      [groupId]
    );
    res.json(rows);
  } finally { conn.release(); }
});

// post message
app.post('/api/groups/:id/messages', authMiddleware, async (req, res) => {
  const groupId = +req.params.id;
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Empty message' });
  const conn = await pool.getConnection();
  try {
    await conn.query('INSERT INTO group_messages (group_id, user_id, message) VALUES (?, ?, ?)', [groupId, req.user.id, message]);
    res.json({ ok: true });
  } finally { conn.release(); }
});

app.listen(process.env.PORT || 4000, () => {
  console.log('Server listening on', process.env.PORT || 4000);
});
