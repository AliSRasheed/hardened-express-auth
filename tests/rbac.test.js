import { beforeEach, describe, expect, it } from 'vitest';
import { requireRole } from '../src/middleware/rbac.js';
import { createTestApp, expectError, get, signIn, userId } from './helpers.js';

const ADMIN_ONLY = '/api/admin/users';
const MANAGERS_AND_ADMINS = '/api/reports';

describe('role-based access', () => {
  let app;

  beforeEach(() => {
    app = createTestApp();
  });

  describe(`GET ${ADMIN_ONLY}`, () => {
    it.each(['guest', 'manager'])('refuses a %s with 403 FORBIDDEN', async (role) => {
      const cookie = await signIn(app, role);

      expectError(await get(app, ADMIN_ONLY, cookie), 403, 'FORBIDDEN');
    });

    it('lets an admin in', async () => {
      const cookie = await signIn(app, 'admin');

      expect((await get(app, ADMIN_ONLY, cookie)).status).toBe(200);
    });

    it('lists every user with public fields only, never a password hash', async () => {
      const res = await get(app, ADMIN_ONLY, await signIn(app, 'admin'));

      expect(res.body.data).toHaveLength(app.locals.users.list().length);
      for (const user of res.body.data) {
        expect(Object.keys(user).sort()).toEqual(['email', 'id', 'name', 'role']);
      }
      expect(JSON.stringify(res.body)).not.toContain('$2');
    });
  });

  describe(`GET ${MANAGERS_AND_ADMINS}`, () => {
    it('refuses a guest with 403 FORBIDDEN', async () => {
      const cookie = await signIn(app, 'guest');

      expectError(await get(app, MANAGERS_AND_ADMINS, cookie), 403, 'FORBIDDEN');
    });

    it.each(['manager', 'admin'])('lets the %s in', async (role) => {
      const cookie = await signIn(app, role);

      expect((await get(app, MANAGERS_AND_ADMINS, cookie)).status).toBe(200);
    });
  });

  it.each([ADMIN_ONLY, MANAGERS_AND_ADMINS])(
    'answers %s without a cookie with 401, not 403 (sign-in is checked before the role)',
    async (path) => {
      expectError(await get(app, path), 401, 'NOT_SIGNED_IN');
    },
  );

  it('applies a role taken away in the store to the very next request', async () => {
    const cookie = await signIn(app, 'admin');
    expect((await get(app, ADMIN_ONLY, cookie)).status).toBe(200);

    app.locals.users.update(userId(app, 'admin'), { role: 'guest' });

    expectError(await get(app, ADMIN_ONLY, cookie), 403, 'FORBIDDEN');
  });

  it('applies a role granted in the store to the very next request', async () => {
    const cookie = await signIn(app, 'guest');
    expectError(await get(app, ADMIN_ONLY, cookie), 403, 'FORBIDDEN');

    app.locals.users.update(userId(app, 'guest'), { role: 'admin' });

    expect((await get(app, ADMIN_ONLY, cookie)).status).toBe(200);
  });
});

describe('requireRole', () => {
  // Fails closed: a route set up without roles must not start, rather than let everyone through.
  it('throws at setup when called with no roles', () => {
    expect(() => requireRole()).toThrow();
  });

  // A misspelt constant such as ROLES.ADMNI is undefined. It must stop the app, not build a check.
  it('throws at setup when its only role is undefined', () => {
    expect(() => requireRole(undefined)).toThrow();
  });

  it('throws at setup when any one of its roles is undefined', () => {
    expect(() => requireRole('admin', undefined)).toThrow();
  });
});
