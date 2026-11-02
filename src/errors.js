export class AppError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
  }
}

export function notFound(req, res, next) {
  next(new AppError(404, 'NOT_FOUND', 'That address does not exist.'));
}

// Turns the errors we expect into AppErrors. Anything else stays unknown and becomes a 500.
function asAppError(err) {
  if (err instanceof AppError) return err;
  if (err.type === 'entity.parse.failed') {
    return new AppError(400, 'VALIDATION_ERROR', 'The request body is not valid JSON.');
  }
  if (err.type === 'entity.too.large') {
    return new AppError(413, 'PAYLOAD_TOO_LARGE', 'The request is too large.');
  }
  return null;
}

// Express only treats a function with four arguments as an error handler.
export function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  const known = asAppError(err);
  if (known) {
    return res.status(known.status).json({ error: { code: known.code, message: known.message } });
  }

  console.error(err);
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Something went wrong on our side.' } });
}
