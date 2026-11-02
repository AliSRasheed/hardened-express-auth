import { AppError } from '../errors.js';
import { SESSION_COOKIE, verifySession } from '../session.js';
import { toPublicUser } from '../users.js';

export const notSignedIn = () => new AppError(401, 'NOT_SIGNED_IN', 'Please sign in first.');

// A factory so the secret createApp() validated at startup is bound in, rather than read from the environment per request.
// Loads req.user fresh from the store on every request, so a role changed or a user removed in the store
// applies at once and nothing in the token beyond `sub` is trusted.
export function createRequireAuth(secret) {
  return function requireAuth(req, res, next) {
    const token = req.cookies?.[SESSION_COOKIE];
    const payload = typeof token === 'string' ? verifySession(token, secret) : null;
    const user = typeof payload?.sub === 'string' ? req.app.locals.users.findById(payload.sub) : null;
    if (!user) return next(notSignedIn());

    req.user = toPublicUser(user);
    next();
  };
}
