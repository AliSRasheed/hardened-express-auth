// TODO: an express-rate-limit instance per call (so each app has its own count), standard RateLimit headers,
// and a 429 TOO_MANY_REQUESTS AppError. This stub never limits.
export function createLoginLimiter({ limit, windowMs }) {
  return (req, res, next) => next();
}
