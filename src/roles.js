export const ROLES = Object.freeze({
  ADMIN: 'admin',
  MANAGER: 'manager',
  GUEST: 'guest',
});

export const MANAGER_ROLES = Object.freeze([ROLES.MANAGER, ROLES.ADMIN]);
