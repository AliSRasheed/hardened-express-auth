import { AppError } from '../errors.js';
import { SESSION_COOKIE, verifySession } from '../session.js';
import { toPublicUser } from '../users.js';

const notSignedIn = () => new AppError(401, 'NOT_SIGNED_IN', 'Please sign in first.');

// Loads req.user fresh from the store on every request, so a role changed or a user removed in the store
// applies at once and nothing in the token beyond `sub` is trusted.
export function requireAuth(req, res, next) {
  const token = req.cookies?.[SESSION_COOKIE];
  const payload = typeof token === 'string' ? verifySession(token) : null;
  const user = typeof payload?.sub === 'string' ? req.app.locals.users.findById(payload.sub) : null;
  if (!user) return next(notSignedIn());

  req.user = toPublicUser(user);
  next();
}
