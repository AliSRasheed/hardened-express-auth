import cookieParser from 'cookie-parser';
import express from 'express';
import { AppError, errorHandler, notFound } from './errors.js';
import { createLockout } from './lockout.js';
import { requireAuth } from './middleware/auth.js';
import { createLoginLimiter } from './middleware/rateLimit.js';
import { requireRole } from './middleware/rbac.js';
import { MANAGER_ROLES, ROLES } from './roles.js';
import { createUserStore } from './users.js';

const FIFTEEN_MINUTES = 15 * 60 * 1000;

// The IP limit sits above the lockout threshold, so one account's guesser meets the lockout first
// and the IP limiter catches spraying across many accounts.
export const DEFAULTS = Object.freeze({
  ipLimit: 20,
  windowMs: FIFTEEN_MINUTES,
  maxFailedLogins: 5,
  lockMs: FIFTEEN_MINUTES,
});

const notImplemented = (req, res, next) => next(new AppError(501, 'NOT_IMPLEMENTED', 'This route is not built yet.'));

// A factory, not a singleton: each app has its own user store, IP limiter and lockout counts, so tests never share state.
export function createApp(options = {}) {
  const { ipLimit, windowMs, maxFailedLogins, lockMs, bcryptCost } = { ...DEFAULTS, ...options };
  // TODO: refuse to start when JWT_SECRET is missing or shorter than 32 characters.

  const app = express();
  app.disable('x-powered-by');
  app.locals.users = createUserStore({ bcryptCost });
  app.locals.lockout = createLockout({ maxFailedLogins, lockMs });

  app.use(express.json({ limit: '10kb' }));
  app.use(cookieParser());

  app.get('/health', (req, res) => res.json({ data: { status: 'ok' } }));

  app.post('/api/auth/login', createLoginLimiter({ limit: ipLimit, windowMs }), notImplemented);
  app.post('/api/auth/logout', notImplemented);
  app.get('/api/me', requireAuth, notImplemented);
  app.get('/api/reports', requireAuth, requireRole(...MANAGER_ROLES), notImplemented);
  app.get('/api/admin/users', requireAuth, requireRole(ROLES.ADMIN), notImplemented);

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
