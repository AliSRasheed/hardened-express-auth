import jwt from 'jsonwebtoken';

// The __Host- prefix makes the browser refuse this cookie unless it is Secure, on Path=/ and has no Domain,
// so a sibling subdomain can never plant or overwrite it.
export const SESSION_COOKIE = '__Host-session';

const ALGORITHM = 'HS256';
const SESSION_HOURS = 8;
export const SESSION_MS = SESSION_HOURS * 60 * 60 * 1000;

// Used by clearCookie, which must name the same attributes as the cookie it clears or browsers keep the old one.
export const CLEAR_COOKIE_OPTIONS = Object.freeze({
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
});

export const SESSION_COOKIE_OPTIONS = Object.freeze({ ...CLEAR_COOKIE_OPTIONS, maxAge: SESSION_MS });

// Read on every call rather than at import, so createApp() (and the tests) decide the secret.
const secret = () => process.env.JWT_SECRET;

// The token names its user and nothing else: the role is loaded fresh from the store on every request.
export function signSession(user) {
  return jwt.sign({ sub: user.id }, secret(), { algorithm: ALGORITHM, expiresIn: `${SESSION_HOURS}h` });
}

// Pinning the algorithm refuses alg "none" and any other HMAC variant. Any failure means "not signed in".
export function verifySession(token) {
  try {
    return jwt.verify(token, secret(), { algorithms: [ALGORITHM] });
  } catch {
    return null;
  }
}
