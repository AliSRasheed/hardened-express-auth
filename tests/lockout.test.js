import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CREDENTIALS, MINUTE, UNKNOWN_EMAIL, WRONG_PASSWORD, createTestApp, expectError, login } from './helpers.js';

const LOCK_MS = 15 * MINUTE;
const { admin, manager } = CREDENTIALS;

describe('lockout per account', () => {
  let app;

  async function failLogins(email, count) {
    for (let attempt = 1; attempt <= count; attempt += 1) {
      expectError(await login(app, email, WRONG_PASSWORD), 401, 'INVALID_CREDENTIALS');
    }
  }

  async function lock(email) {
    await failLogins(email, 4);
    expectError(await login(app, email, WRONG_PASSWORD), 429, 'ACCOUNT_LOCKED');
  }

  beforeEach(() => {
    app = createTestApp();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('answers 4 wrong passwords with 401, then locks on the 5th with 429 ACCOUNT_LOCKED', async () => {
    await failLogins(admin.email, 4);

    expectError(await login(app, admin.email, WRONG_PASSWORD), 429, 'ACCOUNT_LOCKED');
  });

  it('refuses even the correct password while locked, and sets no cookie', async () => {
    await lock(admin.email);

    const res = await login(app, admin.email, admin.password);

    expectError(res, 429, 'ACCOUNT_LOCKED');
    expect(res.headers['set-cookie']).toBeUndefined();
  });

  it('lets the correct password in once lockMs has passed', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    await lock(admin.email);
    const lockedAt = Date.now();

    vi.setSystemTime(lockedAt + LOCK_MS - 1000);
    expectError(await login(app, admin.email, admin.password), 429, 'ACCOUNT_LOCKED');

    vi.setSystemTime(lockedAt + LOCK_MS + 1000);
    expect((await login(app, admin.email, admin.password)).status).toBe(200);
  });

  it('starts the count again after a successful login', async () => {
    await failLogins(admin.email, 4);
    expect((await login(app, admin.email, admin.password)).status).toBe(200);

    await failLogins(admin.email, 4);
  });

  it('counts failures against the normalised email (trimmed, lower case)', async () => {
    await failLogins('Admin@Example.com ', 4);

    expectError(await login(app, 'admin@example.com', WRONG_PASSWORD), 429, 'ACCOUNT_LOCKED');
    expectError(await login(app, 'admin@example.com', admin.password), 429, 'ACCOUNT_LOCKED');
  });

  // If unknown emails never locked, "429 or 401" would tell an attacker which emails have accounts.
  it('locks an unknown email exactly like a real one, with the same status and body at every step', async () => {
    for (let attempt = 1; attempt <= 6; attempt += 1) {
      const known = await login(app, admin.email, WRONG_PASSWORD);
      const unknown = await login(app, UNKNOWN_EMAIL, WRONG_PASSWORD);

      if (attempt < 5) expectError(known, 401, 'INVALID_CREDENTIALS');
      else expectError(known, 429, 'ACCOUNT_LOCKED');
      expect(unknown.status).toBe(known.status);
      expect(unknown.body).toEqual(known.body);
    }
  });

  it('leaves other accounts alone', async () => {
    await lock(admin.email);

    expectError(await login(app, manager.email, WRONG_PASSWORD), 401, 'INVALID_CREDENTIALS');
    expect((await login(app, manager.email, manager.password)).status).toBe(200);
  });
});
