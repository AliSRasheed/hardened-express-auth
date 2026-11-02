# hardened-express-auth

![CI](https://github.com/AliSRasheed/hardened-express-auth/actions/workflows/ci.yml/badge.svg)

A small Express 5 service that shows three authentication controls done carefully, each backed by tests:

1. **Session JWT in a hardened cookie**: `__Host-session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, 8-hour lifetime, HS256 pinned on verify.
2. **Route-level role-based access control (RBAC)**: roles are reloaded from the user store on every request, never trusted from the token, and the role middleware fails closed when it is misconfigured.
3. **Two-layer login throttling**: a per-IP rate limit plus a per-account lockout. The lockout treats unknown emails exactly like real ones, so it doesn't reveal which accounts exist.

It was extracted and rebuilt from the auth layer of a larger hotel-management project (LuxuryStay HMS). Rebuilding it on its own surfaced a user-enumeration flaw in the original lockout, which is fixed here (see [Threat model](#threat-model)).

> This is a focused demo, not a drop-in auth library. Users live in memory and the rate-limit and lockout state is per process. See [Limitations](#limitations).

## Quick start

Requires **Node.js 22.12+**.

```bash
npm install
cp .env.example .env        # Windows PowerShell: Copy-Item .env.example .env
```

Put a random secret of at least 32 characters in `.env`:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

```
JWT_SECRET=<paste the output>
PORT=3000
```

```bash
npm test        # run the full test suite (54 tests)
npm run dev     # start on http://localhost:3000 with auto-reload
```

The app refuses to start if `JWT_SECRET` is missing or shorter than 32 characters.

**Demo accounts:** `admin@example.com`, `manager@example.com` and `guest@example.com`. Their passwords are in `SEED_USERS` in `src/users.js`. They are public demo values, so never reuse them.

## API

| Method | Path | Access | Success |
|---|---|---|---|
| GET | `/health` | public | `200 { data: { status: "ok" } }` |
| POST | `/api/auth/login` | public, rate-limited | `200 { data: user }` + sets `__Host-session` |
| POST | `/api/auth/logout` | public | `200 { data: { signedOut: true } }`, clears the cookie |
| GET | `/api/me` | any signed-in user | `200 { data: user }` |
| GET | `/api/reports` | `manager`, `admin` | `200 { data: { reports: [] } }` |
| GET | `/api/admin/users` | `admin` | `200 { data: [users] }` (public fields only) |

Every error has the same shape, `{ "error": { "code": "...", "message": "..." } }`:

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | Missing or empty email or password, or malformed JSON |
| 401 | `INVALID_CREDENTIALS` | Wrong password **or** unknown email. The two responses are identical. |
| 401 | `NOT_SIGNED_IN` | No cookie, or a token that is invalid, expired or forged |
| 403 | `FORBIDDEN` | Signed in, but the role isn't allowed on this route |
| 404 | `NOT_FOUND` | No route matches the method and path |
| 413 | `PAYLOAD_TOO_LARGE` | JSON body over 10 kb |
| 429 | `TOO_MANY_REQUESTS` | Per-IP login limit hit (sends `RateLimit` and `Retry-After` headers) |
| 429 | `ACCOUNT_LOCKED` | Per-account lockout active (sends `Retry-After`) |
| 500 | `INTERNAL_ERROR` | Any unexpected error. The details go to `console.error`, never to the client. |

## How a request flows

```
POST /api/auth/login
  → IP rate limiter (20 / 15 min, counts every attempt)
  → validate body (trim + lowercase email)           → 400
  → lockout check for this email                     → 429 ACCOUNT_LOCKED
  → bcrypt compare (dummy hash if the email is unknown)
  → re-check lock                                    → 429 ACCOUNT_LOCKED
      fail    → record failure (known AND unknown emails)
                → 5th failure starts a lock           → 429 ACCOUNT_LOCKED
                → otherwise                           → 401 INVALID_CREDENTIALS
      success → reset counter → set cookie → 200

GET /api/admin/users
  → requireAuth: read cookie → verify HS256 JWT (startup-bound secret)
                → reload user by `sub` from the store → 401 if missing
  → requireRole('admin'): role from the store, not the token → 403
  → handler
```

## Design decisions

- **The cookie, not localStorage.** `HttpOnly` means page JavaScript, including injected scripts, can't read the token.
- **`__Host-` prefix.** Browsers only accept this cookie if it has `Secure`, `Path=/` and no `Domain`, so the browser enforces the flags as well as the server.
- **Always `Secure`.** The original project only set `Secure` in production. Browsers treat `localhost` as a secure context, so local development still works.
- **The token carries only `sub`.** Roles are looked up on every request, so a role change or a deleted user takes effect on the next request.
- **The secret is bound at startup.** `createApp()` validates `JWT_SECRET` once and passes it in. Changing the environment variable later does nothing.
- **RBAC fails closed.** `requireRole()` throws at setup if it is given no roles, or a role that is `undefined` (for example a misspelt constant). The app won't start rather than leave a route open.
- **`createApp()` is a factory.** Each instance has its own user store, limiter and lockout, which keeps the tests isolated.
- **Tests were written first.** The suite was written before the implementation, and each feature was built until its tests passed.

## Threat model

**What's protected:** user sessions, the role-gated routes, and the confidentiality of which emails have accounts.
**Attackers considered:** anonymous internet users, signed-in users with a low-privilege role, and a malicious website the victim visits.

| Threat | Control | Tested |
|---|---|---|
| A script steals the session token (XSS) | `HttpOnly` cookie | ✅ cookie flags |
| The token is sent over plain HTTP | `Secure` + `__Host-` prefix | ✅ |
| A forged or tampered token, `alg: none`, or an algorithm swap | `jwt.verify` with `algorithms: ['HS256']`, secret bound at startup | ✅ tampered, expired, other-secret, alg-none, HS512 |
| Privilege escalation by editing token claims | Role reloaded from the store; the token holds only `sub` | ✅ role change applies on the next request |
| A misconfigured route left open | `requireRole` fails closed at setup | ✅ no roles, an `undefined` role, and an `undefined` among valid roles |
| Online password guessing against one account | Lockout: 5 failures → 15 min | ✅ |
| Password spraying across many accounts | Per-IP limit: 20 attempts / 15 min | ✅ default limit; ⚠️ window not tested |
| Account enumeration through responses | Identical 401 bodies; unknown emails lock exactly like real ones | ✅ |
| Account enumeration through timing | bcrypt compare against a dummy hash for unknown emails | ⚠️ not timing-tested |
| Memory exhaustion through millions of fake emails | Lockout entries expire; store capped at 10,000 entries | ✅ cap test |
| Race: a correct guess finishing after a parallel request started a lock | Lock re-checked after the password compare | ⚠️ not tested |
| Cross-site request forgery (CSRF) on state-changing routes | `SameSite=Lax`; JSON-only body parsing (form posts get 400) | partly |

**A real problem this rebuild caught.** In the original project, only existing accounts were ever locked. After 5 wrong passwords a real email got `429` while an unknown email kept getting `401`, which told an attacker which emails were registered. Here the lockout is keyed by the normalised email address, not by the user record, so known and unknown emails behave identically.

## Limitations

These are deliberate trade-offs for a focused demo, written down so nobody mistakes the repo for more than it is:

- **Tokens can't be revoked.** Logout clears the cookie in the browser, but a copied token stays valid until it expires (8 hours, fixed, not sliding). Deleting the user, or rotating `JWT_SECRET`, does end sessions. There is no `iss`, `aud` or `kid`, and no gradual key rotation.
- **Anyone can lock an account.** Knowing an email is enough to lock it for 15 minutes, again and again. Production systems add CAPTCHA, progressive delays or an unlock email.
- **The cap can be abused.** When the lockout store is full, the oldest entry is evicted even if it is an active lock. An attacker with many IPs could push a real lock out early.
- **State is in memory, per process.** It is lost on restart, and with N workers an attacker gets N times the attempts. A shared store such as Redis would fix both.
- **`trust proxy` is off.** Behind a reverse proxy, every client shares one IP bucket, so one attacker could block logins for everyone. Set the exact hop count when deploying behind one.
- **Forced logout is possible.** Another site can submit a top-level POST to `/api/auth/logout`. Login CSRF is blocked only because bodies are JSON-only, and adding `express.urlencoded()` would reopen it.
- **`__Host-` needs a secure context.** It works on `https://` and on `http://localhost` in Chrome and Firefox. Older Safari rejects it. On any other plain-HTTP deployment the cookie is silently dropped.
- **bcrypt reads only the first 72 bytes** of a password. Nothing handles longer passwords.
- **The secret check is length-only.** 32 copies of `a` would pass.
- **The timing defence assumes one bcrypt cost.** If the cost is raised, users still on the old cost become distinguishable until they are rehashed.
- **`/api/admin/users` shows every email to admins.** A real system would paginate and log admin reads.
- **Logging:** unexpected errors go to `console.error`. A real deployment must make sure request bodies, and so passwords, never reach the logs.

## Project layout

```
src/
  app.js               createApp(): routes, login flow, secret check
  session.js           cookie name and options, sign and verify (HS256)
  users.js             in-memory user store and seed
  lockout.js           per-account lockout (expiring, capped)
  server.js            entry point: createApp().listen(PORT)
  roles.js
  errors.js            AppError and the error handler
  middleware/
    auth.js            createRequireAuth(secret)
    rbac.js            requireRole(...roles)
    rateLimit.js       createLoginLimiter(opts)
tests/                 health, cookie, auth, rbac, rateLimit, lockout
```

## Stack

Node.js · Express 5 · jsonwebtoken · cookie-parser · express-rate-limit · bcryptjs · Vitest · supertest
