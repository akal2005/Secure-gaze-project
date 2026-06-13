const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const { db } = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'secure-gaze-default-secret-key-12345';

// Configure CORS
app.use(cors({
  origin: 'http://localhost:5173', // React/Vite dev port
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Helper to get client IP address
function getClientIp(req) {
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor) {
    return forwardedFor.split(',')[0].trim();
  }
  return req.socket.remoteAddress || '127.0.0.1';
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Access token missing' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden: Invalid or expired token' });
    }
    req.user = decoded; // holds { userId, username }
    next();
  });
}

// -------------------------------------------------------------
// Authentication Endpoints
// -------------------------------------------------------------

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, combination, salt } = req.body;

    if (!username || !combination || !salt) {
      return res.status(400).json({ error: 'Username, combination sequence, and salt are required' });
    }

    if (!Array.isArray(combination) || combination.length !== 3) {
      return res.status(400).json({ error: 'Combination must be a 3-number sequence' });
    }

    const existingUser = await db.user.findUnique({
      where: { username: username.toLowerCase() }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Username is already taken' });
    }

    const combinationStr = combination.join('-');
    const passwordHash = await bcrypt.hash(combinationStr, 10);

    const user = await db.user.create({
      data: {
        username: username.toLowerCase(),
        passwordHash,
        salt
      }
    });

    return res.status(201).json({ message: 'User registered successfully', userId: user.id });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ error: 'Internal server error during registration' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  let username = '';
  const ipAddress = getClientIp(req);

  try {
    const { username: reqUsername, combination } = req.body;
    username = reqUsername ? reqUsername.toLowerCase() : '';

    if (!username || !combination) {
      return res.status(400).json({ error: 'Username and combination are required' });
    }

    if (!Array.isArray(combination) || combination.length !== 3) {
      return res.status(400).json({ error: 'Invalid combination format' });
    }

    const user = await db.user.findUnique({
      where: { username }
    });

    if (!user) {
      // Log failed access
      await db.loginAttempt.create({
        data: {
          username,
          ipAddress,
          success: false,
          details: 'User not found'
        }
      });
      return res.status(400).json({ error: 'Invalid username or combination' });
    }

    const combinationStr = combination.join('-');
    const isValid = await bcrypt.compare(combinationStr, user.passwordHash);

    if (!isValid) {
      // Log failed access
      await db.loginAttempt.create({
        data: {
          username,
          ipAddress,
          success: false,
          details: 'Incorrect combination sequence',
          userId: user.id
        }
      });
      return res.status(400).json({ error: 'Invalid username or combination' });
    }

    // Log successful access
    await db.loginAttempt.create({
      data: {
        username,
        ipAddress,
        success: true,
        details: 'Successful auth session',
        userId: user.id
      }
    });

    // Sign JWT token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    return res.json({
      message: 'Login successful',
      token,
      userId: user.id,
      username: user.username,
      salt: user.salt
    });
  } catch (error) {
    console.error('Login error:', error);
    if (username) {
      try {
        await db.loginAttempt.create({
          data: {
            username,
            ipAddress,
            success: false,
            details: `Internal error: ${error.message}`
          }
        });
      } catch (err) {
        console.error('Log error writing fail:', err);
      }
    }
    return res.status(500).json({ error: 'Internal server error during login' });
  }
});

// -------------------------------------------------------------
// Vault Item CRUD Endpoints
// -------------------------------------------------------------

// Read all items
app.get('/api/vault', authenticateToken, async (req, res) => {
  try {
    const items = await db.vaultItem.findMany({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' }
    });
    return res.json({ items });
  } catch (error) {
    console.error('Fetch vault items error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Create item
app.post('/api/vault', authenticateToken, async (req, res) => {
  try {
    const { name, username, value, notes } = req.body;

    if (!name || !username || !value) {
      return res.status(400).json({ error: 'Name, encrypted username, and encrypted password are required' });
    }

    const item = await db.vaultItem.create({
      data: {
        userId: req.user.userId,
        name,
        username,
        value,
        notes
      }
    });

    return res.status(201).json({ message: 'Secret added to vault', item });
  } catch (error) {
    console.error('Create vault item error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Update item
app.put('/api/vault', authenticateToken, async (req, res) => {
  try {
    const { id, name, username, value, notes } = req.body;

    if (!id || !name || !username || !value) {
      return res.status(400).json({ error: 'ID, name, encrypted username, and encrypted password are required' });
    }

    const existingItem = await db.vaultItem.findUnique({
      where: { id }
    });

    if (!existingItem || existingItem.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Secret not found or unauthorized' });
    }

    const updatedItem = await db.vaultItem.update({
      where: { id },
      data: {
        name,
        username,
        value,
        notes
      }
    });

    return res.json({ message: 'Secret updated', item: updatedItem });
  } catch (error) {
    console.error('Update vault item error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete item
app.delete('/api/vault', authenticateToken, async (req, res) => {
  try {
    const { id } = req.query;

    if (!id) {
      return res.status(400).json({ error: 'ID parameter is required' });
    }

    const existingItem = await db.vaultItem.findUnique({
      where: { id }
    });

    if (!existingItem || existingItem.userId !== req.user.userId) {
      return res.status(404).json({ error: 'Secret not found or unauthorized' });
    }

    await db.vaultItem.delete({
      where: { id }
    });

    return res.json({ message: 'Secret deleted from vault' });
  } catch (error) {
    console.error('Delete vault item error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// -------------------------------------------------------------
// Logging Endpoints
// -------------------------------------------------------------
app.get('/api/logs', authenticateToken, async (req, res) => {
  try {
    const attempts = await db.loginAttempt.findMany({
      where: {
        OR: [
          { userId: req.user.userId },
          { username: req.user.username }
        ]
      },
      orderBy: { attemptTime: 'desc' },
      take: 20
    });
    return res.json({ attempts });
  } catch (error) {
    console.error('Logs fetch error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`[Secure Gaze API] Backend active on port ${PORT}`);
});
