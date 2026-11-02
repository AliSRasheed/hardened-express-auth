import { AppError } from '../errors.js';
import { notSignedIn } from './auth.js';

const forbidden = () => new AppError(403, 'FORBIDDEN', 'Your role does not allow this.');

// Runs after requireAuth and checks req.user.role, which requireAuth reloaded from the store: the token's claims never decide a role.
// Fails closed at setup: no roles, or a role that is not a non-empty string (say a misspelt ROLES.ADMNI, which is undefined), throws
// instead of building a check that lets everyone in.
export function requireRole(...roles) {
  if (roles.length === 0 || !roles.every((role) => typeof role === 'string' && role)) {
    throw new Error('requireRole() needs at least one role, each a non-empty string.');
  }
  const allowed = new Set(roles);

  return (req, res, next) => {
    if (!req.user) return next(notSignedIn());
    if (!allowed.has(req.user.role)) return next(forbidden());
    next();
  };
}
