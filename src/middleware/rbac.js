// TODO: 401 without req.user, 403 FORBIDDEN when req.user.role is not one of `roles`. This stub lets everyone through.
export function requireRole(...roles) {
  return (req, res, next) => next();
}
