const { describe, it, before, after, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const {
  app,
  setupTestDatabase,
  cleanupTestDatabase,
  getDatabase,
  generateValidPassword,
  generateValidUsername,
  generateValidEmail,
} = require('./test-helper');

describe('Defensive Control 3: Secure Cookie Settings, Logout & Session Lifecycle', () => {
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

  it('should issue session cookies with HttpOnly and SameSite=Strict flags', async () => {
    const dynamicUser = generateValidUsername('cookie_user');
    const dynamicPass = generateValidPassword();
    const dynamicEmail = generateValidEmail('cookie');

    const res = await request(app)
      .post('/api/auth/register')
      .send({
        username: dynamicUser,
        email: dynamicEmail,
        password: dynamicPass,
      })
      .expect(201);

    const cookies = res.headers['set-cookie'];
    assert.ok(cookies, 'Set-Cookie header must be present');

    const sessionCookie = cookies.find((c) => c.startsWith('sid='));
    assert.ok(sessionCookie, 'Cookie name must match custom identifier "sid"');
    assert.match(sessionCookie, /HttpOnly/i, 'Cookie must include HttpOnly flag to prevent XSS theft');
    assert.match(sessionCookie, /SameSite=Strict/i, 'Cookie must include SameSite=Strict to mitigate CSRF');
    assert.match(sessionCookie, /Path=\//i, 'Cookie must be scoped to root Path=/');
  });

  it('should prevent session fixation by regenerating session ID upon login', async () => {
    const dynamicUser = generateValidUsername('fixation');
    const dynamicPass = generateValidPassword();
    const dynamicEmail = generateValidEmail('fixation');

    // 1. Register a user
    await request(app)
      .post('/api/auth/register')
      .send({
        username: dynamicUser,
        email: dynamicEmail,
        password: dynamicPass,
      })
      .expect(201);

    // 2. Perform an unauthenticated request to acquire an initial pre-session
    const unauthRes = await request(app).get('/');
    const preAuthCookies = unauthRes.headers['set-cookie'] || [];
    const preAuthSid = preAuthCookies.find((c) => c.startsWith('sid='));

    // 3. Log in with credentials
    const loginRes = await request(app)
      .post('/api/auth/login')
      .set('Cookie', preAuthSid || '')
      .send({
        username: dynamicUser,
        password: dynamicPass,
      })
      .expect(200);

    const postAuthCookies = loginRes.headers['set-cookie'];
    assert.ok(postAuthCookies, 'Login must issue a Set-Cookie header');

    const postAuthSid = postAuthCookies.find((c) => c.startsWith('sid='));
    assert.ok(postAuthSid, 'Post-auth session cookie must be present');

    if (preAuthSid) {
      assert.notStrictEqual(
        preAuthSid,
        postAuthSid,
        'Session ID must be regenerated upon authentication to prevent session fixation'
      );
    }
  });

  it('should enforce session authentication on protected endpoints and reject expired/invalid sessions', async () => {
    // 1. Request protected endpoint without session -> 401
    const noSessionRes = await request(app)
      .get('/api/auth/me')
      .expect(401);

    assert.strictEqual(noSessionRes.body.error, 'Authentication required. Please log in.');

    // 2. Request with invalid/tampered session cookie -> 401
    const fakeCookieRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', ['sid=s%3AfakeInvalidSessionId12345.signaturePayload'])
      .expect(401);

    assert.strictEqual(fakeCookieRes.body.error, 'Authentication required. Please log in.');

    // 3. Request with valid active session -> 200
    const validUser = generateValidUsername('protected_user');
    const validPass = generateValidPassword();
    const validEmail = generateValidEmail('protected');

    const regRes = await request(app)
      .post('/api/auth/register')
      .send({
        username: validUser,
        email: validEmail,
        password: validPass,
      })
      .expect(201);

    const validCookie = regRes.headers['set-cookie'];
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', validCookie)
      .expect(200);

    assert.strictEqual(meRes.body.user.username, validUser);
  });

  it('should destroy session on server and clear client cookie upon logout', async () => {
    const logoutUser = generateValidUsername('logout');
    const logoutPass = generateValidPassword();
    const logoutEmail = generateValidEmail('logout');

    // 1. Register & authenticate
    const regRes = await request(app)
      .post('/api/auth/register')
      .send({
        username: logoutUser,
        email: logoutEmail,
        password: logoutPass,
      })
      .expect(201);

    const authCookie = regRes.headers['set-cookie'];

    // 2. Call logout endpoint
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', authCookie)
      .expect(200);

    assert.strictEqual(logoutRes.body.message, 'Logged out successfully.');

    // Verify Set-Cookie header clears the cookie
    const clearedCookies = logoutRes.headers['set-cookie'];
    assert.ok(clearedCookies, 'Logout must issue Set-Cookie header to clear cookie');

    const clearedSid = clearedCookies.find((c) => c.startsWith('sid='));
    assert.ok(clearedSid, 'Cleared cookie must target "sid"');
    assert.match(
      clearedSid,
      /Expires=Thu, 01 Jan 1970|Max-Age=0/i,
      'Cleared cookie must have expired timestamp or Max-Age=0'
    );

    // 3. Verify previous session is completely invalidated on protected endpoint
    const afterLogoutRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', authCookie)
      .expect(401);

    assert.strictEqual(afterLogoutRes.body.error, 'Authentication required. Please log in.');
  });
});
