import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { CREDENTIALS, WRONG_PASSWORD, createTestApp, expectError, get, login } from './helpers.js';

// A high lockout threshold keeps the per-account lockout out of the way, so only the IP limiter can answer 429.
const limitedApp = () => createTestApp({ ipLimit: 3, maxFailedLogins: 100 });

// One wrong password on each of several emails: password spraying from a single IP.
async function spray(app, count) {
  for (let n = 1; n <= count; n += 1) {
    expectError(await login(app, `sprayed.${n}@example.com`, WRONG_PASSWORD), 401, 'INVALID_CREDENTIALS');
  }
}

const correctLogin = (app) => login(app, CREDENTIALS.admin.email, CREDENTIALS.admin.password);

describe('login rate limit per IP', () => {
  it('lets 3 failed logins through, then answers the 4th with 429 TOO_MANY_REQUESTS, even with the right password', async () => {
    const app = limitedApp();

    await spray(app, 3);

    const fourth = await correctLogin(app);
    expectError(fourth, 429, 'TOO_MANY_REQUESTS');
    expect(fourth.headers['set-cookie']).toBeUndefined();
  });

  it('sends the standard RateLimit headers and Retry-After with the 429, and no legacy X-RateLimit headers', async () => {
    const app = limitedApp();
    await spray(app, 3);

    const res = await login(app, 'sprayed.4@example.com', WRONG_PASSWORD);

    expect(res.status).toBe(429);
    expect(res.headers.ratelimit).toBeDefined();
    expect(res.headers['ratelimit-policy']).toBeDefined();
    expect(res.headers['retry-after']).toBeDefined();
    expect(res.headers['x-ratelimit-limit']).toBeUndefined();
  });

  it('keeps a separate count for each app', async () => {
    const first = limitedApp();
    await spray(first, 3);
    expectError(await correctLogin(first), 429, 'TOO_MANY_REQUESTS');

    const second = limitedApp();

    expect((await correctLogin(second)).status).toBe(200);
  });

  it('does not limit other routes', async () => {
    const app = limitedApp();
    await spray(app, 3);
    expectError(await correctLogin(app), 429, 'TOO_MANY_REQUESTS');

    expect((await get(app, '/health')).status).toBe(200);
    expectError(await get(app, '/api/me'), 401, 'NOT_SIGNED_IN');
    expect((await request(app).post('/api/auth/logout')).status).toBe(200);
  });
});
