// TODO: verify the session cookie and load req.user fresh from the store on every request,
// so the role inside the token is never trusted. This stub lets everyone through.
export function requireAuth(req, res, next) {
  next();
}
