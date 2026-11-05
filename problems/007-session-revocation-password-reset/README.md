# 007 · A user reset her password after losing her laptop, and the laptop stayed logged in

## Problem
A B2B expense app keeps users signed in with server-side sessions that last
30 days. A finance manager lost her work laptop on a train, reset her password
from her phone, and assumed that was the end of it. Days later, audit logs
showed the laptop's session still opening reports. Security confirmed that a
password change or reset had never signed out existing sessions, and there
was no "log out of all devices" option, so every account recovery the support
team had ever done had left old sessions alive.

## Root cause
Authentication and session state were **decoupled**: a session, once created,
was checked only for existence and expiry. Changing the password updated the
hash used at the *next login* but did nothing to sessions that had already
logged in. `ReproduceSurvivingSessions` shows the lost laptop's token still
authenticating after a reset.

## Solution
1. **Session epoch per user.** Each session stores the user's
   `session_epoch` at creation and is valid only while it still matches.
   Password reset, password change, "log out everywhere" and admin lockout
   bump the epoch, which revokes every session in O(1), with no scan of the
   session table and no race with sessions being created on other servers.
2. **Keep the caller signed in.** `change_password` revokes everything,
   including the current session, and returns a *fresh* token, so the device
   that made the change stays signed in with a new identifier and every other
   device is out.
3. **Expiry on two clocks.** A 30-minute idle timeout (sliding with
   activity) and a 12-hour absolute lifetime that activity cannot extend.
4. **Hardening.** Tokens are 32 random bytes; only their SHA-256 is stored, so
   a leaked session table cannot be replayed as cookies. Revoked or expired
   sessions are deleted when next seen. Failed password changes (wrong current
   password, too short) revoke nothing. Registering a username that already
   exists is refused, because re-creating the user would restart its epoch
   at 0 and revive sessions that were revoked at epoch 0.

## Trade-offs
- Every request now needs the user's epoch. Cache it next to the session (or
  in the same Redis hash) and invalidate on bump, otherwise this is an extra
  DB read per request.
- Stateless JWT access tokens cannot be revoked this way until they expire.
  Keep them short-lived (minutes) and check the epoch when refreshing, or
  embed the epoch as a claim and compare against a cached value.
- Revoking all sessions is blunt. A per-device session list with selective
  logout is friendlier, and can be built on the same store.
- The scrypt cost (`n=2**12`) is lowered so the tests run fast. In production
  use a stronger setting (e.g. OWASP's scrypt guidance of N=2^17, r=8, p=1)
  or Argon2id.

## Run
```bash
python -m unittest -v test_solution.py
```
