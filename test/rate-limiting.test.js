const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const {
  app,
  setupTestDatabase,
  cleanupTestDatabase,
  generateValidUsername,
  generateValidPassword,
} = require('./test-helper');

describe('Defensive Control 5: Rate Limiting & Brute-Force Throttling', () => {
  before(() => {
    // Explicitly enable rate limit checking for this test suite
    process.env.TEST_ENABLE_RATE_LIMIT = 'true';
    setupTestDatabase();
  });

  after(() => {
    delete process.env.TEST_ENABLE_RATE_LIMIT;
    cleanupTestDatabase();
  });

  it('should throttle repeated authentication attempts and return HTTP 429 when threshold exceeded', async () => {
    const maxAttempts = parseInt(process.env.AUTH_RATE_LIMIT_MAX, 10) || 5;
    const testUsername = generateValidUsername('throttle_test');
    const testPassword = generateValidPassword();

    // Send requests up to the configured limit
    for (let i = 0; i < maxAttempts; i++) {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ username: testUsername, password: testPassword });

      // Before limit is exceeded, server evaluates credentials (401)
      assert.strictEqual(
        res.status,
        401,
        `Attempt ${i + 1} should be evaluated (received ${res.status})`
      );
    }

    // Next request must be throttled with HTTP 429 Too Many Requests
    const throttledRes = await request(app)
      .post('/api/auth/login')
      .send({ username: testUsername, password: testPassword });

    assert.strictEqual(throttledRes.status, 429, 'Excessive attempts must return HTTP 429');
    assert.strictEqual(
      throttledRes.body.error,
      'Too many login attempts, please try again later.',
      'Must return informative rate limit error message'
    );

    // Verify rate limit headers
    assert.ok(
      throttledRes.headers['ratelimit-remaining'] !== undefined ||
      throttledRes.headers['retry-after'] !== undefined,
      'Response must include standard RateLimit or Retry-After headers'
    );
  });
});
