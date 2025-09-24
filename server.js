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
  origin: 'https://studyhub-backend-2.onrender.com', // Your frontend URL
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json());


// --- Database Connection ---
// This defines the `pool` variable correctly at the top level
const pool = new Pool({
  connectionString: process.env.DATABASE_URL, // This uses the single URL from Render's environment variables
  ssl: {
    rejectUnauthorized: false
  }
});


// --- Static Frontend Serving ---
// This serves your index.html and any other frontend files (like css or images)
app.use(express.static(path.join(__dirname, 'frontend')));


// --- API Routes ---

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';

// Helper function to create a JWT
function makeToken(user) {
  return jwt.sign({ id: user.id, email: user.email, display_name: user.display_name }, JWT_SECRET, { expiresIn: '7d' });
}

// Middleware to verify JWT
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

// -- AUTHENTICATION --
app.post('/api/register', async (req, res) => {
  const { email, password, display_name } = req.body;
  if (!email || !password || !display_name) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const existResult = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existResult.rows.length > 0) {
      return res.status(409).json({ error: 'Email already in use' });
    }

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
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = makeToken(user);
    res.json({ token, user: { id: user.id, email: user.email, display_name: user.display_name } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// -- PROFILE & SUBJECTS --
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

// -- GROUPS & MATCHING --
app.post('/api/groups', authMiddleware, async (req, res) => {
  const { title, subject_id, description, level, max_members } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO groups (title, subject_id, description, owner_id, level, max_members)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [title, subject_id, description || '', req.user.id, level || 'mixed', max_members || 10]
    );
    const groupId = result.rows[0].id;
    await pool.query(
      'INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, $3)',
      [groupId, req.user.id, 'owner']
    );
    res.status(201).json({ ok: true, groupId });
  } catch (error) {
    console.error('Create group error:', error);
    res.status(500).json({ error: 'Failed to create group' });
  }
});

app.post('/api/groups/:id/join', authMiddleware, async (req, res) => {
    const groupId = parseInt(req.params.id);
    if (isNaN(groupId)) return res.status(400).json({ error: 'Invalid group ID' });
    
    // All database operations for a single request should ideally be in a transaction
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const groupResult = await client.query('SELECT max_members FROM groups WHERE id = $1 FOR UPDATE', [groupId]);
        if (groupResult.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Group not found' });
        }
        const group = groupResult.rows[0];

        const countResult = await client.query('SELECT COUNT(*) as count FROM group_members WHERE group_id = $1', [groupId]);
        const memberCount = parseInt(countResult.rows[0].count);

        if (memberCount >= group.max_members) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Group is full' });
        }
        
        const existsResult = await client.query('SELECT * FROM group_members WHERE group_id = $1 AND user_id = $2', [groupId, req.user.id]);
        if (existsResult.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Already a member' });
        }

        await client.query('INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)', [groupId, req.user.id]);
        
        await client.query('COMMIT');
        res.json({ ok: true });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Join group error:', error);
        res.status(500).json({ error: 'Failed to join group' });
    } finally {
        client.release();
    }
});

app.get('/api/match', authMiddleware, async (req, res) => {
  const { subject_id, level, type } = req.query;
  try {
    if (type === 'group') {
      const result = await pool.query(
        `SELECT g.*, s.name AS subject_name, u.display_name as owner_name,
         (SELECT COUNT(*) FROM group_members gm WHERE gm.group_id = g.id) as member_count
         FROM groups g
         JOIN subjects s ON s.id = g.subject_id
         JOIN users u ON u.id = g.owner_id
         WHERE g.subject_id = $1 ${level ? 'AND (g.level = $2 OR g.level = \'mixed\')' : ''}
         ORDER BY g.created_at DESC LIMIT 50`,
        level ? [subject_id, level] : [subject_id]
      );
      return res.json(result.rows);
    } else {
      const result = await pool.query(
        `SELECT u.id, u.display_name, p.bio, us.level, s.name as subject_name
         FROM user_subjects us
         JOIN users u ON u.id = us.user_id
         LEFT JOIN profiles p ON p.user_id = u.id
         JOIN subjects s ON s.id = us.subject_id
         WHERE us.subject_id = $1 ${level ? 'AND us.level = $2' : ''}
         LIMIT 50`,
        level ? [subject_id, level] : [subject_id]
      );
      return res.json(result.rows);
    }
  } catch (error) {
    console.error('Match error:', error);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

app.get('/api/groups/:id/messages', authMiddleware, async (req, res) => {
  const groupId = parseInt(req.params.id);
  try {
    const result = await pool.query(
      `SELECT gm.*, u.display_name FROM group_messages gm 
       JOIN users u ON u.id = gm.user_id 
       WHERE gm.group_id = $1 ORDER BY gm.sent_at ASC LIMIT 200`,
      [groupId]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Messages error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.post('/api/groups/:id/messages', authMiddleware, async (req, res) => {
  const groupId = parseInt(req.params.id);
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
  res.json({ message: 'API is working!' });
});


// --- Frontend Catch-all ---
// This must be the LAST route so it doesn't interfere with API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});


// --- Server Start ---
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});