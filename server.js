// server.js
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// PostgreSQL connection
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
app.use(express.static(__dirname));

// Main route - serve index.html
app.get('/', (req, res) => {
  const frontendIndex = path.join(__dirname, 'frontend', 'index.html');
  const rootIndex = path.join(__dirname, 'index.html');
  
  // Try frontend folder first, then root
  const fs = require('fs');
  if (fs.existsSync(frontendIndex)) {
    res.sendFile(frontendIndex);
  } else if (fs.existsSync(rootIndex)) {
    res.sendFile(rootIndex);
  } else {
    res.send(`
      <h1>StudyHub Backend is Running!</h1>
      <p>Frontend files not found. Please check:</p>
      <ul>
        <li>index.html should be in /frontend/ folder</li>
        <li>Or in the root directory</li>
      </ul>
      <p>API is available at /api/ endpoints</p>
    `);
  }
});

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

// Helper functions
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
  
  try {
    // Check if user exists
    const existResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existResult.rows.length) return res.status(400).json({ error: 'Email in use' });
    
    // Hash password and create user
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id',
      [email, hash, display_name]
    );
    
    const user = { id: result.rows[0].id, email, display_name };
    const token = makeToken(user);
    res.json({ token, user });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const result = await pool.query(
      'SELECT id, email, password_hash, display_name FROM users WHERE email = $1',
      [email]
    );
    
    if (!result.rows.length) return res.status(400).json({ error: 'Invalid credentials' });
    
    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'Invalid credentials' });
    
    const token = makeToken(user);
    res.json({ token, user: { id: user.id, email: user.email, display_name: user.display_name } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

/* ========== PROFILE & SUBJECTS ========== */

// set profile
app.post('/api/profile', authMiddleware, async (req, res) => {
  const { bio, location, availability } = req.body;
  
  try {
    await pool.query(
      `INSERT INTO profiles (user_id, bio, location, availability) VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE SET bio = $2, location = $3, availability = $4`,
      [req.user.id, bio||null, location||null, availability||null]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// add/update user subject+level
app.post('/api/user/subject', authMiddleware, async (req, res) => {
  const { subject_id, level } = req.body;
  if (!subject_id || !level) return res.status(400).json({ error: 'Missing fields' });
  
  try {
    await pool.query(
      `INSERT INTO user_subjects (user_id, subject_id, level) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, subject_id) DO UPDATE SET level = $3`,
      [req.user.id, subject_id, level]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('User subject error:', error);
    res.status(500).json({ error: 'Failed to update subject' });
  }
});

// list subjects
app.get('/api/subjects', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM subjects ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Subjects error:', error);
    res.status(500).json({ error: 'Failed to fetch subjects' });
  }
});

/* ========== GROUPS & MATCHING ========== */

// create group
app.post('/api/groups', authMiddleware, async (req, res) => {
  const { title, subject_id, description, level, max_members } = req.body;
  
  try {
    const result = await pool.query(
      `INSERT INTO groups (title, subject_id, description, owner_id, level, max_members)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [title, subject_id, description||'', req.user.id, level||'mixed', max_members||10]
    );
    
    const groupId = result.rows[0].id;
    await pool.query(
      'INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3)',
      [groupId, req.user.id, 'owner']
    );
    
    res.json({ ok: true, groupId });
  } catch (error) {
    console.error('Create group error:', error);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

// join group
app.post('/api/groups/:id/join', authMiddleware, async (req, res) => {
  const groupId = +req.params.id;
  
  try {
    // Check if group exists and get max members
    const groupResult = await pool.query('SELECT max_members FROM groups WHERE id = $1', [groupId]);
    if (!groupResult.rows.length) return res.status(404).json({ error: 'Group not found' });
    
    const group = groupResult.rows[0];
    
    // Check current member count
    const countResult = await pool.query('SELECT COUNT(*) as count FROM group_members WHERE group_id = $1', [groupId]);
    const memberCount = parseInt(countResult.rows[0].count) || 0;
    
    // Check if user is already a member
    const existsResult = await pool.query('SELECT * FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, req.user.id]);
    if (existsResult.rows.length) return res.status(400).json({ error: 'Already a member' });
    
    // Check if group is full
    if (memberCount >= group.max_members) return res.status(400).json({ error: 'Group full' });
    
    // Add user to group
    await pool.query('INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)', [groupId, req.user.id]);
    res.json({ ok: true });
  } catch (error) {
    console.error('Join group error:', error);
    res.status(500).json({ error: 'Failed to join group' });
  }
});

// search for matching users or groups
app.get('/api/match', authMiddleware, async (req, res) => {
  const { subject_id, level, type } = req.query;
  
  try {
    if (type === 'group') {
      const query = `
        SELECT g.*, s.name AS subject_name, u.display_name as owner_name,
               (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count
        FROM groups g
        JOIN subjects s ON s.id = g.subject_id
        JOIN users u ON u.id = g.owner_id
        WHERE g.subject_id = $1 ${level ? 'AND (g.level = $2 OR g.level = \'mixed\')' : ''}
        ORDER BY g.created_at DESC
        LIMIT 50
      `;
      
      const result = await pool.query(query, level ? [subject_id, level] : [subject_id]);
      return res.json(result.rows);
    } else {
      const query = `
        SELECT u.id, u.display_name, p.bio, us.level, s.name as subject_name
        FROM user_subjects us
        JOIN users u ON u.id = us.user_id
        LEFT JOIN profiles p ON p.user_id = u.id
        JOIN subjects s ON s.id = us.subject_id
        WHERE us.subject_id = $1 ${level ? 'AND us.level = $2' : ''}
        LIMIT 50
      `;
      
      const result = await pool.query(query, level ? [subject_id, level] : [subject_id]);
      return res.json(result.rows);
    }
  } catch (error) {
    console.error('Match error:', error);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

// get group messages
app.get('/api/groups/:id/messages', authMiddleware, async (req, res) => {
  const groupId = +req.params.id;
  
  try {
    const result = await pool.query(
      `SELECT gm.*, u.display_name 
       FROM group_messages gm 
       JOIN users u ON u.id = gm.user_id 
       WHERE gm.group_id = $1 
       ORDER BY gm.sent_at ASC 
       LIMIT 200`,
      [groupId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Messages error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// post message
app.post('/api/groups/:id/messages', authMiddleware, async (req, res) => {
  const groupId = +req.params.id;
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'Empty message' });
  
  try {
    await pool.query(
      'INSERT INTO group_messages (group_id, user_id, message) VALUES ($1, $2, $3)',
      [groupId, req.user.id, message]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('Post message error:', error);
    res.status(500).json({ error: 'Failed to post message' });
  }
});

// Test endpoint
app.get('/api/test', (req, res) => {
  res.json({ message: 'API is working!', timestamp: new Date().toISOString() });
});

app.listen(process.env.PORT || 4000, () => {
  console.log('Server listening on', process.env.PORT || 4000);
});