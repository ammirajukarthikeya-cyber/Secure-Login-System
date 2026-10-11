const express = require('express');
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const {
  createUser,
  findUserByUsername,
  findUserByEmail,
  findUserById,
} = require('../db/database');
const { requireFullAuth } = require('../middleware/auth');
const { logSecurityEvent } = require('../middleware/logger');

const router = express.Router();

const crypto = require('crypto');

// Configurable bcrypt cost factor (defaults to 12 for high resistance against brute-force)
function getBcryptRounds() {
  const rounds = parseInt(process.env.BCRYPT_ROUNDS, 10);
  return Number.isInteger(rounds) && rounds >= 4 ? rounds : 12;
}

// Dynamically generated dummy hash for constant-time timing-attack mitigation
// Zero static or hardcoded hashes/passwords in source code
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), getBcryptRounds());

// ---------------------------------------------------------------------------
// Server-side Input Validation Rules
// ---------------------------------------------------------------------------
const registerValidation = [
  body('username')
    .trim()
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be 3-30 characters.')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username may only contain letters, numbers, and underscores.'),
  body('email')
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address.'),
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters.')
    .matches(/[A-Z]/)
    .withMessage('Password must contain at least one uppercase letter.')
    .matches(/[a-z]/)
    .withMessage('Password must contain at least one lowercase letter.')
    .matches(/[0-9]/)
    .withMessage('Password must contain at least one number.')
    .matches(/[^A-Za-z0-9]/)
    .withMessage('Password must contain at least one special character.'),
];

const loginValidation = [
  body('username')
    .trim()
    .notEmpty()
    .withMessage('Username is required.')
    .isLength({ max: 50 })
    .withMessage('Username cannot exceed 50 characters.'),
  body('password')
    .notEmpty()
    .withMessage('Password is required.')
    .isLength({ max: 128 })
    .withMessage('Password cannot exceed 128 characters.'),
];

// ---------------------------------------------------------------------------
// POST /api/auth/register
// ---------------------------------------------------------------------------
router.post('/register', registerValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: errors.array()[0].msg,
      errors: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }

  const { username, email, password } = req.body;

  try {
    // Check for existing account collisions
    if (findUserByUsername(username)) {
      logSecurityEvent({
        event: 'AUTH_REGISTER_COLLISION',
        level: 'WARN',
        req,
        username,
        details: { reason: 'username_exists' },
      });
      return res.status(409).json({ error: 'Username is already taken.' });
    }
    if (findUserByEmail(email)) {
      logSecurityEvent({
        event: 'AUTH_REGISTER_COLLISION',
        level: 'WARN',
        req,
        username,
        details: { reason: 'email_exists' },
      });
      return res.status(409).json({ error: 'Email is already registered.' });
    }

    // Hash password with salt and work factor
    const rounds = getBcryptRounds();
    const passwordHash = await bcrypt.hash(password, rounds);

    // Persist user with hashed credential
    const result = createUser(username, email, passwordHash);

    // Prevent Session Fixation: Regenerate session ID upon account creation
    req.session.regenerate((err) => {
      if (err) {
        logSecurityEvent({
          event: 'SECURITY_SYSTEM_ERROR',
          level: 'ERROR',
          req,
          details: { action: 'session_regenerate_register', message: err.message },
        });
        return res.status(500).json({ error: 'Session error.' });
      }
      req.session.userId = result.lastInsertRowid;
      req.session.username = username;
      req.session.requires2FA = false;
      req.session.save((saveErr) => {
        if (saveErr) {
          return res.status(500).json({ error: 'Session save error.' });
        }

        logSecurityEvent({
          event: 'AUTH_REGISTER_SUCCESS',
          req,
          userId: result.lastInsertRowid,
          username,
        });

        res.status(201).json({
          message: 'Registration successful!',
          user: { id: result.lastInsertRowid, username, email },
        });
      });
    });
  } catch (err) {
    logSecurityEvent({
      event: 'SECURITY_SYSTEM_ERROR',
      level: 'ERROR',
      req,
      details: { action: 'register', message: err.message },
    });
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/login
// ---------------------------------------------------------------------------
router.post('/login', loginValidation, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: errors.array()[0].msg,
      errors: errors.array().map((e) => ({ field: e.path, message: e.msg })),
    });
  }

  const { username, password } = req.body;

  try {
    const user = findUserByUsername(username);

    // Defensive Timing Mitigation:
    // Execute bcrypt.compare even if user does not exist to avoid side-channel timing leaks
    const hashToCompare = user ? user.password_hash : DUMMY_HASH;
    const match = await bcrypt.compare(password, hashToCompare);

    // Generic authentication failure response to prevent username enumeration
    if (!user || !match) {
      logSecurityEvent({
        event: 'AUTH_LOGIN_FAILURE',
        level: 'WARN',
        req,
        details: { reason: 'invalid_credentials' },
      });
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Prevent Session Fixation: Regenerate session ID upon successful login
    req.session.regenerate((err) => {
      if (err) {
        logSecurityEvent({
          event: 'SECURITY_SYSTEM_ERROR',
          level: 'ERROR',
          req,
          details: { action: 'session_regenerate_login', message: err.message },
        });
        return res.status(500).json({ error: 'Session error.' });
      }

      req.session.userId = user.id;
      req.session.username = user.username;

      if (user.totp_enabled) {
        req.session.requires2FA = true;
        req.session.save((saveErr) => {
          if (saveErr) {
            return res.status(500).json({ error: 'Session save error.' });
          }

          logSecurityEvent({
            event: 'AUTH_LOGIN_STEP1_SUCCESS',
            req,
            userId: user.id,
            username: user.username,
            details: { mfa_required: true },
          });

          res.json({
            message: 'Two-factor authentication required.',
            requires2FA: true,
          });
        });
      } else {
        req.session.requires2FA = false;
        req.session.save((saveErr) => {
          if (saveErr) {
            return res.status(500).json({ error: 'Session save error.' });
          }

          logSecurityEvent({
            event: 'AUTH_LOGIN_SUCCESS',
            req,
            userId: user.id,
            username: user.username,
            details: { mfa_required: false },
          });

          res.json({
            message: 'Login successful!',
            requires2FA: false,
            user: { id: user.id, username: user.username, email: user.email },
          });
        });
      }
    });
  } catch (err) {
    logSecurityEvent({
      event: 'SECURITY_SYSTEM_ERROR',
      level: 'ERROR',
      req,
      details: { action: 'login', message: err.message },
    });
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ---------------------------------------------------------------------------
// POST /api/auth/logout
// ---------------------------------------------------------------------------
router.post('/logout', (req, res) => {
  const cookieName = process.env.SESSION_COOKIE_NAME || 'sid';
  const userId = req.session?.userId;
  const username = req.session?.username;

  if (!req.session) {
    res.clearCookie(cookieName, { path: '/' });
    return res.json({ message: 'Logged out successfully.' });
  }

  req.session.destroy((err) => {
    if (err) {
      logSecurityEvent({
        event: 'SECURITY_SYSTEM_ERROR',
        level: 'ERROR',
        req,
        userId,
        username,
        details: { action: 'logout', message: err.message },
      });
      return res.status(500).json({ error: 'Could not log out.' });
    }

    logSecurityEvent({
      event: 'AUTH_LOGOUT',
      req,
      userId,
      username,
    });

    // Clear session cookie on browser client
    res.clearCookie(cookieName, { path: '/' });
    res.json({ message: 'Logged out successfully.' });
  });
});

// ---------------------------------------------------------------------------
// GET /api/auth/me
// ---------------------------------------------------------------------------
router.get('/me', requireFullAuth, (req, res) => {
  const user = findUserById(req.session.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }
  res.json({
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      totpEnabled: !!user.totp_enabled,
      createdAt: user.created_at,
    },
  });
});

module.exports = router;
