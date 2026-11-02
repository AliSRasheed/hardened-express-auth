import jwt from 'jsonwebtoken';
import request from 'supertest';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  CREDENTIALS,
  EIGHT_HOURS_IN_SECONDS,
  TEST_SECRET,
  UNKNOWN_EMAIL,
  WRONG_PASSWORD,
  createTestApp,
  expectError,
  login,
  sessionCookie,
  userId,
} from './helpers.js';

const { admin, guest } = CREDENTIALS;

describe('POST /api/auth/login', () => {
  let app;

  beforeEach(() => {
    app = createTestApp();
  });

  it('signs in and sets an HttpOnly, Secure, SameSite=Lax cookie on / for 8 hours', async () => {
    const res = await login(app, guest.email, guest.password);

    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ email: guest.email, role: 'guest' });
    const cookie = sessionCookie(res);
    expect(cookie).toBeDefined();
    const attributes = cookie
      .split(';')
      .slice(1)
      .map((attribute) => attribute.trim());
    expect(attributes).toEqual(
      expect.arrayContaining(['HttpOnly', 'Secure', 'SameSite=Lax', 'Path=/', 'Max-Age=28800']),
    );
  });

  it('puts an HS256 JWT naming the user, valid for 8 hours, in the cookie', async () => {
    const res = await login(app, guest.email, guest.password);

    expect(res.status).toBe(200);
    const token = sessionCookie(res).split(';')[0].split('=')[1];
    const { header, payload } = jwt.decode(token, { complete: true });
    expect(header.alg).toBe('HS256');
    expect(payload.sub).toBe(userId(app, 'guest'));
    expect(payload.exp - payload.iat).toBe(EIGHT_HOURS_IN_SECONDS);
    expect(() => jwt.verify(token, TEST_SECRET, { algorithms: ['HS256'] })).not.toThrow();
  });

  it('answers a wrong password with 401 INVALID_CREDENTIALS and sets no cookie', async () => {
    const res = await login(app, admin.email, WRONG_PASSWORD);

    expectError(res, 401, 'INVALID_CREDENTIALS');
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('gives an unknown email the identical status and body as a wrong password', async () => {
    const wrongPassword = await login(app, admin.email, WRONG_PASSWORD);
    const unknownEmail = await login(app, UNKNOWN_EMAIL, WRONG_PASSWORD);

    expectError(wrongPassword, 401, 'INVALID_CREDENTIALS');
    expect(unknownEmail.status).toBe(wrongPassword.status);
    expect(unknownEmail.body).toEqual(wrongPassword.body);
    expect(unknownEmail.headers['set-cookie']).toBeUndefined();
  });

  it.each([
    ['no body at all', undefined],
    ['no password', { email: admin.email }],
    ['no email', { password: admin.password }],
    ['empty strings', { email: '', password: '' }],
    ['values that are not strings', { email: ['admin@example.com'], password: 12345678 }],
  ])('answers %s with 400 VALIDATION_ERROR', async (_, body) => {
    const res = await request(app).post('/api/auth/login').send(body);

    expectError(res, 400, 'VALIDATION_ERROR');
    expect(res.headers['set-cookie']).toBeUndefined();
  });
});
