import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import { ROLES } from './roles.js';

export const BCRYPT_COST = 12;

// Demo accounts for a local demo only. These passwords are public, so never seed them anywhere real.
export const SEED_USERS = Object.freeze([
  { name: 'Ada Admin', email: 'admin@example.com', password: 'Admin-Demo-Pass-1', role: ROLES.ADMIN },
  { name: 'Mo Manager', email: 'manager@example.com', password: 'Manager-Demo-Pass-1', role: ROLES.MANAGER },
  { name: 'Gil Guest', email: 'guest@example.com', password: 'Guest-Demo-Pass-1', role: ROLES.GUEST },
]);

export const normaliseEmail = (email) => String(email).trim().toLowerCase();

export function toPublicUser({ id, name, email, role }) {
  return { id, name, email, role };
}

// One store per app, seeded on creation. Ids are random, so a token from one app never names a user in another.
export function createUserStore({ bcryptCost = BCRYPT_COST } = {}) {
  const byId = new Map();
  for (const { password, ...fields } of SEED_USERS) {
    const id = randomUUID();
    byId.set(id, { id, ...fields, passwordHash: bcrypt.hashSync(password, bcryptCost) });
  }

  return {
    findById: (id) => byId.get(id) ?? null,
    findByEmail(email) {
      const wanted = normaliseEmail(email);
      return [...byId.values()].find((user) => user.email === wanted) ?? null;
    },
    list: () => [...byId.values()],
    update(id, fields) {
      const user = byId.get(id);
      if (user) Object.assign(user, fields);
      return user ?? null;
    },
  };
}
