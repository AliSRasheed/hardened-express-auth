import { rateLimit } from 'express-rate-limit';
import { AppError } from '../errors.js';

// A new limiter, with its own in-memory count, on every call, so each app counts separately.
// Every request counts, successful logins and 400s included. The library sets Retry-After before calling the handler.
// `trust proxy` is off, so behind a reverse proxy every client shares the proxy's IP.
export function createLoginLimiter({ limit, windowMs }) {
  return rateLimit({
    limit,
    windowMs,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    handler: (req, res, next) => {
      next(new AppError(429, 'TOO_MANY_REQUESTS', 'Too many sign-in attempts from your address. Try again later.'));
    },
  });
}
