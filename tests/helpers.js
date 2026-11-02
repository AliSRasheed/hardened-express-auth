import jwt from 'jsonwebtoken';
import request from 'supertest';
import { expect } from 'vitest';
import { createApp } from '../src/app.js';
import { SESSION_COOKIE } from '../src/session.js';
import { SEED_USERS } from '../src/users.js';

// Set in vitest.config.js. A test-only value.
export const TEST_SECRET = process.env.JWT_SECRET;

export const MINUTE = 60 * 1000;
export const EIGHT_HOURS_IN_SECONDS = 8 * 60 * 60;

// The seeded demo accounts by role: CREDENTIALS.admin.email, CREDENTIALS.admin.password, and so on.
export const CREDENTIALS = Object.fromEntries(
  SEED_USERS.map(({ role, email, password }) => [role, { email, password }]),
);
export const WRONG_PASSWORD = 'Not-The-Password-9';
export const UNKNOWN_EMAIL = 'nobody.here@example.com';

// A low bcrypt cost keeps seeding fast; bcrypt compares any cost the same way.
export const createTestApp = (options) => createApp({ bcryptCost: 4, ...options });

export const login = (app, email, password) => request(app).post('/api/auth/login').send({ email, password });

export const sessionCookie = (res) =>
  res.headers['set-cookie']?.find((cookie) => cookie.startsWith(`${SESSION_COOKIE}=`));

// Signs in a seeded account and returns the "name=value" pair to send back as a Cookie header.
export async function signIn(app, role) {
  const { email, password } = CREDENTIALS[role];
  const res = await login(app, email, password);
  expect(res.status).toBe(200);
  const cookie = sessionCookie(res);
  expect(cookie).toBeDefined();
  return cookie.split(';')[0];
}

export const get = (app, path, cookie) => {
  const req = request(app).get(path);
  return cookie ? req.set('Cookie', cookie) : req;
};

export const cookieFor = (token) => `${SESSION_COOKIE}=${token}`;

export const userId = (app, role) => app.locals.users.findByEmail(CREDENTIALS[role].email).id;

// The session token names its user in `sub`. Tests craft tokens directly to probe how they are verified.
export const signToken = (payload, { secret = TEST_SECRET, algorithm = 'HS256' } = {}) =>
  jwt.sign(payload, secret, { algorithm, expiresIn: EIGHT_HOURS_IN_SECONDS });

export const base64url = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

// Every error answer has exactly this shape: { error: { code, message } }.
export function expectError(res, status, code) {
  expect(res.status).toBe(status);
  expect(res.body).toEqual({ error: { code, message: expect.any(String) } });
}
