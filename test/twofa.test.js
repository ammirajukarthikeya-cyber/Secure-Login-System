const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const speakeasy = require('speakeasy');
const {
  app,
  setupTestDatabase,
  cleanupTestDatabase,
  getDatabase,
  generateValidPassword,
  generateValidUsername,
  generateValidEmail,
} = require('./test-helper');

describe('Defensive Control 6: Two-Factor Authentication (TOTP)', () => {
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

  it('should enforce full 2FA lifecycle: setup, verify, login challenge, and guarded access', async () => {
    const mfaUser = generateValidUsername('mfa');
    const mfaPassword = generateValidPassword();
    const mfaEmail = generateValidEmail('mfa');

    // 1. Register a user
    const regRes = await request(app)
      .post('/api/auth/register')
      .send({
        username: mfaUser,
        email: mfaEmail,
        password: mfaPassword,
      })
      .expect(201);

    const userCookie = regRes.headers['set-cookie'];

    // 2. Setup 2FA - obtain TOTP secret
    const setupRes = await request(app)
      .post('/api/2fa/setup')
      .set('Cookie', userCookie)
      .expect(200);

    assert.ok(setupRes.body.secret, 'Must return base32 secret');
    assert.ok(setupRes.body.qrCode, 'Must return QR code data URL');
    const secret = setupRes.body.secret;

    // 3. Verify 2FA with invalid token -> 401
    await request(app)
      .post('/api/2fa/verify')
      .set('Cookie', userCookie)
      .send({ token: '000000' })
      .expect(401);

    // 4. Verify 2FA with valid token -> 200 (Enables 2FA)
    const validToken = speakeasy.totp({
      secret,
      encoding: 'base32',
    });

    const verifyRes = await request(app)
      .post('/api/2fa/verify')
      .set('Cookie', userCookie)
      .send({ token: validToken })
      .expect(200);

    assert.strictEqual(verifyRes.body.message, 'Two-factor authentication enabled successfully!');

    // 5. Logout
    await request(app)
      .post('/api/auth/logout')
      .set('Cookie', userCookie)
      .expect(200);

    // 6. Login with password -> triggers 2FA challenge
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({
        username: mfaUser,
        password: mfaPassword,
      })
      .expect(200);

    assert.strictEqual(loginRes.body.requires2FA, true);
    assert.strictEqual(loginRes.body.user, undefined, 'User data must not be returned before 2FA completion');

    const mfaPendingCookie = loginRes.headers['set-cookie'];

    // 7. Verify protected route is blocked (403 Forbidden) while 2FA challenge is pending
    const blockedRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', mfaPendingCookie)
      .expect(403);

    assert.strictEqual(blockedRes.body.error, 'Two-factor authentication required.');

    // 8. Validate 2FA code
    const challengeToken = speakeasy.totp({
      secret,
      encoding: 'base32',
    });

    const validateRes = await request(app)
      .post('/api/2fa/validate')
      .set('Cookie', mfaPendingCookie)
      .send({ token: challengeToken })
      .expect(200);

    assert.strictEqual(validateRes.body.user.username, mfaUser);
    const postMfaCookie = validateRes.headers['set-cookie'] || mfaPendingCookie;

    // 9. Verify protected route is now accessible (200 OK) using post-2FA session
    const authedRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', postMfaCookie)
      .expect(200);

    assert.strictEqual(authedRes.body.user.username, mfaUser);
    assert.strictEqual(authedRes.body.user.totpEnabled, true);
  });
});
