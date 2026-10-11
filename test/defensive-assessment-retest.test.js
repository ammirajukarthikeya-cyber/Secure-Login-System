const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const {
  app,
  setupTestDatabase,
  cleanupTestDatabase,
  getDatabase,
  generateValidPassword,
  generateValidUsername,
  generateValidEmail,
} = require('./test-helper');
const { getRawUserById } = require('../db/database');
const { decryptSecret } = require('../utils/crypto');

describe('Capstone Retest Suite: Defensive Hardening & Verification', () => {
  before(() => {
    setupTestDatabase();
  });

  after(() => {
    cleanupTestDatabase();
  });

  beforeEach(() => {
    const db = getDatabase();
    db.exec('DELETE FROM users;');
  });

  // =========================================================================
  // DOMAIN 1: CONFIGURATION SECURITY
  // =========================================================================
  describe('Domain 1: Configuration Hardening', () => {
    it('should enforce strict Content Security Policy without unsafe-inline in script-src', async () => {
      const res = await request(app).get('/').expect(200);
      const csp = res.headers['content-security-policy'];
      assert.ok(csp, 'Content-Security-Policy header must be present');
      assert.match(csp, /script-src 'self'/, 'script-src must strictly allow only self');
      assert.doesNotMatch(
        csp,
        /script-src[^;]*'unsafe-inline'/,
        "script-src directive MUST NOT allow 'unsafe-inline'"
      );
    });

    it('should return HTTP 400 Bad Request on malformed JSON body without leaking server internals', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .set('Content-Type', 'application/json')
        .send('{ invalid_json: broken')
        .expect(400);

      assert.strictEqual(res.body.error, 'Malformed JSON payload.');
    });
  });

  // =========================================================================
  // DOMAIN 2: AUTHENTICATION & SESSION SECURITY
  // =========================================================================
  describe('Domain 2: Authentication & 2FA Hardening', () => {
    it('should store TOTP secret encrypted at rest (AES-256-GCM) in the database', async () => {
      const dynamicUser = generateValidUsername('crypto_user');
      const dynamicPass = generateValidPassword();
      const dynamicEmail = generateValidEmail('crypto');

      // 1. Register user
      const regRes = await request(app)
        .post('/api/auth/register')
        .send({
          username: dynamicUser,
          email: dynamicEmail,
          password: dynamicPass,
        })
        .expect(201);

      const cookie = regRes.headers['set-cookie'];
      const userId = regRes.body.user.id;

      // 2. Setup 2FA
      const setupRes = await request(app)
        .post('/api/2fa/setup')
        .set('Cookie', cookie)
        .expect(200);

      const plaintextSecret = setupRes.body.secret;
      assert.ok(plaintextSecret, 'Should return plaintext base32 secret in API response for user setup');

      // 3. Inspect raw database record directly
      const rawUser = getRawUserById(userId);
      assert.ok(rawUser, 'User record must exist in DB');
      assert.notStrictEqual(
        rawUser.totp_secret,
        plaintextSecret,
        'TOTP secret must NOT be stored as plaintext base32 in database'
      );

      // Verify format is iv:tag:ciphertext (AES-256-GCM)
      const parts = rawUser.totp_secret.split(':');
      assert.strictEqual(parts.length, 3, 'Encrypted secret format must be iv:tag:ciphertext');
      assert.strictEqual(parts[0].length, 24, 'IV length in hex must be 12 bytes (24 hex characters)');
      assert.strictEqual(parts[1].length, 32, 'Auth tag length in hex must be 16 bytes (32 hex characters)');

      // Verify decryption produces the exact original plaintext secret
      const decrypted = decryptSecret(rawUser.totp_secret);
      assert.strictEqual(decrypted, plaintextSecret, 'Decrypted secret must match original base32 secret');
    });

    it('should prevent session fixation across 2FA validation by regenerating session ID', async () => {
      const dynamicUser = generateValidUsername('fixation_user');
      const dynamicPass = generateValidPassword();
      const dynamicEmail = generateValidEmail('fixation');

      // 1. Register & enable 2FA
      const regRes = await request(app)
        .post('/api/auth/register')
        .send({
          username: dynamicUser,
          email: dynamicEmail,
          password: dynamicPass,
        })
        .expect(201);

      const setupCookie = regRes.headers['set-cookie'];
      const setupRes = await request(app)
        .post('/api/2fa/setup')
        .set('Cookie', setupCookie)
        .expect(200);

      const secret = setupRes.body.secret;
      const enableToken = speakeasy.totp({ secret, encoding: 'base32' });

      await request(app)
        .post('/api/2fa/verify')
        .set('Cookie', setupCookie)
        .send({ token: enableToken })
        .expect(200);

      await request(app).post('/api/auth/logout').set('Cookie', setupCookie).expect(200);

      // 2. Perform step-1 login (password) -> acquire 2FA-pending session cookie
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({
          username: dynamicUser,
          password: dynamicPass,
        })
        .expect(200);

      assert.strictEqual(loginRes.body.requires2FA, true);
      const preMfaCookie = loginRes.headers['set-cookie'];
      assert.ok(preMfaCookie, 'Step-1 login must return session cookie');

      // 3. Complete 2FA validation
      const challengeToken = speakeasy.totp({ secret, encoding: 'base32' });
      const validateRes = await request(app)
        .post('/api/2fa/validate')
        .set('Cookie', preMfaCookie)
        .send({ token: challengeToken })
        .expect(200);

      const postMfaCookie = validateRes.headers['set-cookie'];
      assert.ok(postMfaCookie, 'Validate 2FA endpoint must issue a new Set-Cookie header');

      const preSid = preMfaCookie.find((c) => c.startsWith('sid='));
      const postSid = postMfaCookie.find((c) => c.startsWith('sid='));

      assert.notStrictEqual(
        preSid,
        postSid,
        'Session ID MUST be regenerated upon 2FA validation to eliminate session fixation'
      );
    });

    it('should reject OTP token replay attempts within the validity window', async () => {
      const dynamicUser = generateValidUsername('replay_user');
      const dynamicPass = generateValidPassword();
      const dynamicEmail = generateValidEmail('replay');

      // 1. Setup user with 2FA
      const regRes = await request(app)
        .post('/api/auth/register')
        .send({
          username: dynamicUser,
          email: dynamicEmail,
          password: dynamicPass,
        })
        .expect(201);

      const setupCookie = regRes.headers['set-cookie'];
      const setupRes = await request(app)
        .post('/api/2fa/setup')
        .set('Cookie', setupCookie)
        .expect(200);

      const secret = setupRes.body.secret;
      const enableToken = speakeasy.totp({ secret, encoding: 'base32' });

      await request(app)
        .post('/api/2fa/verify')
        .set('Cookie', setupCookie)
        .send({ token: enableToken })
        .expect(200);

      await request(app).post('/api/auth/logout').set('Cookie', setupCookie).expect(200);

      // 2. Login to get 2FA challenge session
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({
          username: dynamicUser,
          password: dynamicPass,
        })
        .expect(200);

      const preMfaCookie = loginRes.headers['set-cookie'];
      const otpCode = speakeasy.totp({ secret, encoding: 'base32' });

      // 3. First submission with otpCode -> 200 OK
      const firstAttempt = await request(app)
        .post('/api/2fa/validate')
        .set('Cookie', preMfaCookie)
        .send({ token: otpCode })
        .expect(200);

      assert.strictEqual(firstAttempt.body.user.username, dynamicUser);

      // 4. Second submission (Replay Attack) with the exact same otpCode -> 401 Unauthorized
      // Even if another login attempt occurs in the same time step
      const loginRes2 = await request(app)
        .post('/api/auth/login')
        .send({
          username: dynamicUser,
          password: dynamicPass,
        })
        .expect(200);

      const replayMfaCookie = loginRes2.headers['set-cookie'];

      const replayAttempt = await request(app)
        .post('/api/2fa/validate')
        .set('Cookie', replayMfaCookie)
        .send({ token: otpCode })
        .expect(401);

      assert.strictEqual(
        replayAttempt.body.error,
        'Invalid or previously used 2FA token.'
      );
    });

    it('should validate 2FA tokens strictly with server-side validation rules', async () => {
      const dynamicUser = generateValidUsername('val_user');
      const dynamicPass = generateValidPassword();
      const dynamicEmail = generateValidEmail('val');

      const regRes = await request(app)
        .post('/api/auth/register')
        .send({
          username: dynamicUser,
          email: dynamicEmail,
          password: dynamicPass,
        })
        .expect(201);

      const cookie = regRes.headers['set-cookie'];

      // Non-numeric token
      const resAlpha = await request(app)
        .post('/api/2fa/validate')
        .set('Cookie', cookie)
        .send({ token: 'abcdef' })
        .expect(400);

      assert.strictEqual(resAlpha.body.error, 'Token must be a 6-digit number.');

      // Short token
      const resShort = await request(app)
        .post('/api/2fa/validate')
        .set('Cookie', cookie)
        .send({ token: '123' })
        .expect(400);

      assert.strictEqual(resShort.body.error, 'Token must be a 6-digit number.');
    });
  });

  // =========================================================================
  // DOMAIN 5: SECURITY LOGGING & OBSERVABILITY
  // =========================================================================
  describe('Domain 5: Defensive Security Audit Logging', () => {
    it('should sanitize logged details and never expose passwords or secret tokens', () => {
      const { sanitizeDetails } = require('../middleware/logger');
      const samplePayload = {
        user_identifier: generateValidUsername('test_aud'),
        password: generateValidPassword(),
        token: '123456',
        totp_secret: crypto.randomBytes(16).toString('hex'),
        nested: {
          password: generateValidPassword(),
          safeField: 'harmless_metric',
        },
      };

      const sanitized = sanitizeDetails(samplePayload);
      assert.strictEqual(sanitized.user_identifier, samplePayload.user_identifier);
      assert.strictEqual(sanitized.password, '[REDACTED]');
      assert.strictEqual(sanitized.token, '[REDACTED]');
      assert.strictEqual(sanitized.totp_secret, '[REDACTED]');
      assert.strictEqual(sanitized.nested.password, '[REDACTED]');
      assert.strictEqual(sanitized.nested.safeField, 'harmless_metric');
    });
  });
});
