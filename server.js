require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');
const { initDatabase } = require('./db/database');
const authRoutes = require('./routes/auth');
const twofaRoutes = require('./routes/twofa');
const { logSecurityEvent } = require('./middleware/logger');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Reverse Proxy Trust Configuration
// Enables secure extraction of remote client IPs behind load balancers/proxies
// ---------------------------------------------------------------------------
app.set('trust proxy', process.env.TRUST_PROXY ? parseInt(process.env.TRUST_PROXY, 10) : 1);

// ---------------------------------------------------------------------------
// Database Initialization
// ---------------------------------------------------------------------------
initDatabase();

// ---------------------------------------------------------------------------
// Security Headers (Helmet)
// Mitigates Clickjacking, Cross-Site Scripting, MIME-sniffing, etc.
// Hardened CSP: Removed 'unsafe-inline' from scriptSrc to prevent DOM/XSS injection.
// ---------------------------------------------------------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:', 'blob:'],
        connectSrc: ["'self'"],
      },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  })
);

// ---------------------------------------------------------------------------
// Rate Limiting (Defensive Brute-Force & Credential Stuffing Controls)
// ---------------------------------------------------------------------------
const generalWindowMs = parseInt(process.env.GENERAL_RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000;
const generalMax = parseInt(process.env.GENERAL_RATE_LIMIT_MAX, 10) || 100;

const generalLimiter = rateLimit({
  windowMs: generalWindowMs,
  max: generalMax,
  skip: (_req) => process.env.NODE_ENV === 'test' && process.env.TEST_ENABLE_RATE_LIMIT !== 'true',
  handler: (req, res, _next, options) => {
    logSecurityEvent({
      event: 'SECURITY_RATE_LIMIT_EXCEEDED',
      level: 'WARN',
      req,
      details: { limiter: 'general', windowMs: generalWindowMs, max: generalMax },
    });
    res.status(options.statusCode).json(options.message);
  },
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const authWindowMs = parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS, 10) || 15 * 60 * 1000;
const authMax = parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 10;

const authLimiter = rateLimit({
  windowMs: authWindowMs,
  max: authMax,
  skip: (_req) => process.env.NODE_ENV === 'test' && process.env.TEST_ENABLE_RATE_LIMIT !== 'true',
  handler: (req, res, _next, options) => {
    logSecurityEvent({
      event: 'SECURITY_RATE_LIMIT_EXCEEDED',
      level: 'WARN',
      req,
      details: { limiter: 'auth', windowMs: authWindowMs, max: authMax, path: req.originalUrl },
    });
    res.status(options.statusCode).json(options.message);
  },
  message: { error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

// ---------------------------------------------------------------------------
// Body Parsing
// ---------------------------------------------------------------------------
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ---------------------------------------------------------------------------
// Session Management & Cookie Hardening
// ---------------------------------------------------------------------------
let sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  if (process.env.NODE_ENV === 'production') {
    console.error('FATAL: SESSION_SECRET environment variable is strictly required in production mode.');
    process.exit(1);
  }
  // Generate an ephemeral high-entropy random key for local development
  sessionSecret = crypto.randomBytes(32).toString('hex');
}

const isProduction = process.env.NODE_ENV === 'production';
const cookieSecure = isProduction || process.env.COOKIE_SECURE === 'true';
const sessionMaxAge = parseInt(process.env.SESSION_MAX_AGE_MS, 10) || 30 * 60 * 1000; // 30 minutes
const cookieName = process.env.SESSION_COOKIE_NAME || 'sid';

const sessionStore =
  process.env.NODE_ENV === 'test' && process.env.USE_MEMORY_STORE === 'true'
    ? new session.MemoryStore()
    : new SQLiteStore({
        db: process.env.SESSION_DB_NAME || 'sessions.sqlite',
        dir: process.env.SESSION_DB_DIR || path.join(__dirname, 'db'),
        concurrentDB: true,
      });

app.use(
  session({
    store: sessionStore,
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    name: cookieName,
    cookie: {
      httpOnly: true, // Mitigate XSS-based session hijacking
      secure: cookieSecure, // Enforce HTTPS-only cookie transmission
      sameSite: 'strict', // Mitigate Cross-Site Request Forgery (CSRF)
      maxAge: sessionMaxAge, // Inactivity / absolute session timeout
      path: '/',
    },
  })
);

// ---------------------------------------------------------------------------
// Static Assets
// ---------------------------------------------------------------------------
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// API Routes
// Hardened Defense: Both Auth and 2FA endpoints are protected under authLimiter
// ---------------------------------------------------------------------------
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api/2fa', authLimiter, twofaRoutes);

// ---------------------------------------------------------------------------
// SPA Fallback (Single Page Application routing)
// ---------------------------------------------------------------------------
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------------------------------------------------------------------
// Error Handling Middleware (Handles Malformed JSON cleanly and logs errors)
// ---------------------------------------------------------------------------
app.use((err, req, res, _next) => {
  if (err instanceof SyntaxError && (err.status === 400 || err.statusCode === 400)) {
    logSecurityEvent({
      event: 'SECURITY_MALFORMED_INPUT',
      level: 'WARN',
      req,
      details: { error: 'malformed_json_body' },
    });
    return res.status(400).json({ error: 'Malformed JSON payload.' });
  }

  logSecurityEvent({
    event: 'SECURITY_SYSTEM_ERROR',
    level: 'ERROR',
    req,
    details: { error: err.message },
  });
  res.status(500).json({ error: 'Internal server error.' });
});

// ---------------------------------------------------------------------------
// Start Server (Only when run directly, not when required by tests)
// ---------------------------------------------------------------------------
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n🔐  Secure Login System running at http://localhost:${PORT}\n`);
  });
}

module.exports = app;
