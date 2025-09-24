require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

// --- App & Middleware Setup ---
const app = express();

const corsOptions = {
  origin: 'https://studyhub-backend-2.onrender.com', // Change to your frontend URL
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());

// --- Database Connection ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// --- Static Frontend Serving ---
app.use(express.static(path.join(__dirname, 'frontend')));

// --- JWT Helper ---
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
function makeToken(user) {
  return jwt.sign({ id: user.id, email: user.email, display_name: user.display_name }, JWT_SECRET, { expiresIn: '7d' });
}

// --- Auth Middleware ---
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided or malformed header' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// --- API Routes ---

app.post('/api/register', async (req, res) => {
  const { email, password, display_name } = req.body;
  if (!email || !password || !display_name) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const existResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existResult.rows.length > 0) return res.status(409).json({ error: 'Email already in use' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3) RETURNING id, email, display_name',
      [email, hash, display_name]
    );
    const user = result.rows[0];
    const token = makeToken(user);
    res.status(201).json({ token, user });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) return res.status(401).json({ error: 'Invalid credentials' });
    const token = makeToken(user);
    res.json({ token, user: { id: user.id, email: user.email, display_name: user.display_name } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/profile', authMiddleware, async (req, res) => {
  const { bio, location, availability } = req.body;
  try {
    await pool.query(
      `INSERT INTO profiles (user_id, bio, location, availability) VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE SET bio = EXCLUDED.bio, location = EXCLUDED.location, availability = EXCLUDED.availability`,
      [req.user.id, bio || null, location || null, availability || null]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.post('/api/user/subject', authMiddleware, async (req, res) => {
  const { subject_id, level } = req.body;
  if (!subject_id || !level) return res.status(400).json({ error: 'Missing fields' });
  try {
    await pool.query(
      `INSERT INTO user_subjects (user_id, subject_id, level) VALUES ($1, $2, $3)
       ON CONFLICT (user_id, subject_id) DO UPDATE SET level = EXCLUDED.level`,
      [req.user.id, subject_id, level]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error('User subject error:', error);
    res.status(500).json({ error: 'Failed to update user subject' });
  }
});

app.get('/api/subjects', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM subjects ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Subjects error:', error);
    res.status(500).json({ error: 'Failed to fetch subjects' });
  }
});

// --- Add other API routes (groups, messages, match) here exactly as before ---


// --- Test endpoint ---
app.get('/api/test', (req, res) => {
  res.json({ message: 'API is working!' });
});

// --- Frontend Catch-all (React/Vue SPA support) ---
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// --- Server Start ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
