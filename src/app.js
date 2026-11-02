import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import express from 'express';
import { randomUUID } from 'node:crypto';
import { AppError, errorHandler, notFound } from './errors.js';
import { createLockout } from './lockout.js';
import { requireAuth } from './middleware/auth.js';
import { createLoginLimiter } from './middleware/rateLimit.js';
import { requireRole } from './middleware/rbac.js';
import { MANAGER_ROLES, ROLES } from './roles.js';
import { CLEAR_COOKIE_OPTIONS, SESSION_COOKIE, SESSION_COOKIE_OPTIONS, signSession } from './session.js';
import { BCRYPT_COST, createUserStore, normaliseEmail, toPublicUser } from './users.js';

const FIFTEEN_MINUTES = 15 * 60 * 1000;

// The IP limit sits above the lockout threshold, so one account's guesser meets the lockout first
// and the IP limiter catches spraying across many accounts.
export const DEFAULTS = Object.freeze({
  ipLimit: 20,
  windowMs: FIFTEEN_MINUTES,
  maxFailedLogins: 5,
  lockMs: FIFTEEN_MINUTES,
});

const MIN_SECRET_LENGTH = 32;

const notImplemented = (req, res, next) => next(new AppError(501, 'NOT_IMPLEMENTED', 'This route is not built yet.'));

function assertSecret() {
  const secret = process.env.JWT_SECRET;
  if (typeof secret !== 'string' || secret.length < MIN_SECRET_LENGTH) {
    throw new Error(`JWT_SECRET must be set and at least ${MIN_SECRET_LENGTH} characters long.`);
  }
}

// Trims and lower-cases the email before checking it, so "  " counts as missing. The password is used as sent.
function readCredentials(body) {
  const { email, password } = body ?? {};
  const normalised = typeof email === 'string' ? normaliseEmail(email) : '';
  if (!normalised || typeof password !== 'string' || !password) {
    throw new AppError(400, 'VALIDATION_ERROR', 'Send an email and a password.');
  }
  return { email: normalised, password };
}

function createLoginHandler({ users, bcryptCost }) {
  // An unknown email is still compared against a hash of the same cost, so it takes about as long as a real one.
  const dummyHash = bcrypt.hashSync(randomUUID(), bcryptCost);

  return async (req, res) => {
    const { email, password } = readCredentials(req.body);
    const user = users.findByEmail(email);
    const matches = await bcrypt.compare(password, user?.passwordHash ?? dummyHash);
    if (!user || !matches) {
      throw new AppError(401, 'INVALID_CREDENTIALS', 'That email and password do not match.');
    }

    res.cookie(SESSION_COOKIE, signSession(user), SESSION_COOKIE_OPTIONS);
    res.json({ data: toPublicUser(user) });
  };
}

// Always succeeds, signed in or not, so logout never tells anyone whether a session existed.
function logout(req, res) {
  res.clearCookie(SESSION_COOKIE, CLEAR_COOKIE_OPTIONS);
  res.json({ data: { signedOut: true } });
}

// A factory, not a singleton: each app has its own user store, IP limiter and lockout counts, so tests never share state.
export function createApp(options = {}) {
  const { ipLimit, windowMs, maxFailedLogins, lockMs, bcryptCost = BCRYPT_COST } = { ...DEFAULTS, ...options };
  assertSecret();

  const app = express();
  app.disable('x-powered-by');
  app.locals.users = createUserStore({ bcryptCost });
  app.locals.lockout = createLockout({ maxFailedLogins, lockMs });

  app.use(express.json({ limit: '10kb' }));
  app.use(cookieParser());

  app.get('/health', (req, res) => res.json({ data: { status: 'ok' } }));

  app.post(
    '/api/auth/login',
    createLoginLimiter({ limit: ipLimit, windowMs }),
    createLoginHandler({ users: app.locals.users, bcryptCost }),
  );
  app.post('/api/auth/logout', logout);
  app.get('/api/me', requireAuth, (req, res) => res.json({ data: req.user }));
  app.get('/api/reports', requireAuth, requireRole(...MANAGER_ROLES), notImplemented);
  app.get('/api/admin/users', requireAuth, requireRole(ROLES.ADMIN), notImplemented);

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
