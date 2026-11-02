import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  CREDENTIALS,
  base64url,
  cookieFor,
  createTestApp,
  expectError,
  get,
  signIn,
  signToken,
  userId,
} from './helpers.js';

const HOUR_IN_SECONDS = 60 * 60;
const nowInSeconds = () => Math.floor(Date.now() / 1000);

describe('GET /api/me', () => {
  let app;
  const me = (cookie) => get(app, '/api/me', cookie);

  beforeEach(() => {
    app = createTestApp();
  });

  it('answers 401 NOT_SIGNED_IN without a cookie', async () => {
    expectError(await me(), 401, 'NOT_SIGNED_IN');
  });

  // The control for every rejection below: a token crafted the same way, but correctly, is accepted.
  it('accepts a well-formed HS256 token signed with JWT_SECRET', async () => {
    const res = await me(cookieFor(signToken({ sub: userId(app, 'admin') })));

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ email: CREDENTIALS.admin.email, role: 'admin' });
  });

  it('rejects a token whose payload was changed after signing', async () => {
    const [header, , signature] = signToken({ sub: userId(app, 'guest') }).split('.');
    const now = nowInSeconds();
    const forgedPayload = base64url({ sub: userId(app, 'admin'), iat: now, exp: now + HOUR_IN_SECONDS });

    expectError(await me(cookieFor(`${header}.${forgedPayload}.${signature}`)), 401, 'NOT_SIGNED_IN');
  });

  it('rejects an expired token', async () => {
    const nineHoursAgo = nowInSeconds() - 9 * HOUR_IN_SECONDS;
    const token = signToken({ sub: userId(app, 'admin'), iat: nineHoursAgo });

    expectError(await me(cookieFor(token)), 401, 'NOT_SIGNED_IN');
  });

  it('rejects a token signed with a different secret', async () => {
    const token = signToken({ sub: userId(app, 'admin') }, { secret: 'f'.repeat(64) });

    expectError(await me(cookieFor(token)), 401, 'NOT_SIGNED_IN');
  });

  it('rejects an unsigned alg "none" token', async () => {
    const now = nowInSeconds();
    const header = base64url({ alg: 'none', typ: 'JWT' });
    const payload = base64url({ sub: userId(app, 'admin'), iat: now, exp: now + HOUR_IN_SECONDS });

    expectError(await me(cookieFor(`${header}.${payload}.`)), 401, 'NOT_SIGNED_IN');
  });

  it('rejects an HS512 token signed with the right secret (the algorithm is pinned to HS256)', async () => {
    const token = signToken({ sub: userId(app, 'admin') }, { algorithm: 'HS512' });

    expectError(await me(cookieFor(token)), 401, 'NOT_SIGNED_IN');
  });

  it('returns the signed-in user and never the password hash', async () => {
    const cookie = await signIn(app, 'manager');

    const res = await me(cookie);

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({
      id: userId(app, 'manager'),
      email: CREDENTIALS.manager.email,
      role: 'manager',
    });
    const body = JSON.stringify(res.body);
    expect(body).not.toContain('passwordHash');
    expect(body).not.toContain(app.locals.users.findByEmail(CREDENTIALS.manager.email).passwordHash);
  });
});

describe('JWT_SECRET', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('must be set and at least 32 characters long, or createApp refuses to start', () => {
    vi.stubEnv('JWT_SECRET', undefined);
    expect(() => createTestApp()).toThrow(/JWT_SECRET/);

    vi.stubEnv('JWT_SECRET', 'a'.repeat(31));
    expect(() => createTestApp()).toThrow(/JWT_SECRET/);

    vi.stubEnv('JWT_SECRET', 'a'.repeat(32));
    expect(() => createTestApp()).not.toThrow();
  });
});
