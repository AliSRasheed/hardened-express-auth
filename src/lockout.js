import { normaliseEmail } from './users.js';

// Anyone can send any email, so the store is capped rather than allowed to grow with every made-up address.
export const MAX_LOCKOUT_ENTRIES = 10_000;

// Failed sign-ins are counted per normalised email in their own store, not on the user record,
// so an email with no account locks exactly like one that has an account.
//
// Each entry is { failures, locked, since }. `since` is the last failure, or the failure that started the lock,
// and the entry expires lockMs after it. Every write re-inserts its entry, so the Map stays ordered by `since`:
// expired entries are always at the front, and the front is the oldest entry to evict when the store is full.
export function createLockout({ maxFailedLogins, lockMs, maxEntries = MAX_LOCKOUT_ENTRIES }) {
  const entries = new Map();

  const expired = (entry, now) => now - entry.since >= lockMs;

  function prune(now) {
    for (const [email, entry] of entries) {
      if (!expired(entry, now)) break;
      entries.delete(email);
    }
  }

  // Prunes, then returns the live entry for the email, or undefined.
  function read(email, now) {
    prune(now);
    const entry = entries.get(email);
    if (entry && expired(entry, now)) {
      entries.delete(email);
      return undefined;
    }
    return entry;
  }

  function write(email, entry) {
    entries.delete(email);
    if (entries.size >= maxEntries) entries.delete(entries.keys().next().value);
    entries.set(email, entry);
  }

  return {
    isLocked: (email) => read(normaliseEmail(email), Date.now())?.locked === true,

    // Milliseconds until the lock ends, or 0 when the email is not locked. Used for Retry-After.
    lockRemainingMs(email) {
      const now = Date.now();
      const entry = read(normaliseEmail(email), now);
      return entry?.locked ? entry.since + lockMs - now : 0;
    },

    // Returns true when this failure is the one that locks the email. The count restarts at 0 when a lock starts,
    // and a failure during a lock changes nothing, so it cannot extend the lock.
    recordFailure(email) {
      const key = normaliseEmail(email);
      const now = Date.now();
      const entry = read(key, now);
      if (entry?.locked) return false;

      const failures = (entry?.failures ?? 0) + 1;
      const locks = failures >= maxFailedLogins;
      write(key, { failures: locks ? 0 : failures, locked: locks, since: now });
      return locks;
    },

    reset: (email) => {
      entries.delete(normaliseEmail(email));
    },

    size: () => entries.size,
  };
}
