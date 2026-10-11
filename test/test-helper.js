const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// Configure test environment variables dynamically - no static secrets in source code
process.env.NODE_ENV = 'test';
process.env.BCRYPT_ROUNDS = '4'; // Fast rounds for tests while fully verifying bcrypt
process.env.SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
process.env.TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
process.env.SESSION_COOKIE_NAME = 'sid';
process.env.COOKIE_SECURE = 'false';
process.env.AUTH_RATE_LIMIT_WINDOW_MS = '60000'; // 1 minute
process.env.AUTH_RATE_LIMIT_MAX = '5'; // 5 attempts threshold for rate limit test

const TEST_DB_PATH = path.join(__dirname, 'test_app.sqlite');
const TEST_SESSIONS_DIR = __dirname;
const TEST_SESSIONS_DB = 'test_sessions.sqlite';

process.env.DB_PATH = TEST_DB_PATH;
process.env.SESSION_DB_DIR = TEST_SESSIONS_DIR;
process.env.SESSION_DB_NAME = TEST_SESSIONS_DB;

const { initDatabase, closeDatabase, getDatabase } = require('../db/database');
const app = require('../server');

function setupTestDatabase() {
  cleanupTestDatabase();
  initDatabase(TEST_DB_PATH);
}

function cleanupTestDatabase() {
  closeDatabase();
  const filesToDelete = [
    TEST_DB_PATH,
    `${TEST_DB_PATH}-wal`,
    `${TEST_DB_PATH}-shm`,
    path.join(TEST_SESSIONS_DIR, TEST_SESSIONS_DB),
    path.join(TEST_SESSIONS_DIR, `${TEST_SESSIONS_DB}-wal`),
    path.join(TEST_SESSIONS_DIR, `${TEST_SESSIONS_DB}-shm`),
  ];
  for (const f of filesToDelete) {
    if (fs.existsSync(f)) {
      try {
        fs.unlinkSync(f);
      } catch (_) {}
    }
  }
}

/**
 * Dynamically generates compliant credentials at runtime to ensure
 * zero static or hardcoded passwords and usernames exist in test code.
 */
function generateValidPassword() {
  return `P@ssw0rd_${crypto.randomBytes(6).toString('hex')}!Aa`;
}

function generateValidUsername(prefix = 'user') {
  return `${prefix}_${crypto.randomBytes(4).toString('hex')}`;
}

function generateValidEmail(prefix = 'test') {
  return `${prefix}_${crypto.randomBytes(4).toString('hex')}@example.com`;
}

module.exports = {
  app,
  setupTestDatabase,
  cleanupTestDatabase,
  getDatabase,
  TEST_DB_PATH,
  generateValidPassword,
  generateValidUsername,
  generateValidEmail,
};
