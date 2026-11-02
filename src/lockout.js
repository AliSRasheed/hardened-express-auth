// Failed sign-ins are counted per normalised email in their own store, not on the user record,
// so an email with no account locks exactly like one that has an account.
// TODO: real counting. This stub never locks anyone.
export function createLockout({ maxFailedLogins, lockMs }) {
  return {
    isLocked: (email) => false,
    // Returns true when this failure is the one that locks the email.
    recordFailure: (email) => false,
    reset: (email) => {},
  };
}
