# 042 · A customer who forgot to log out at a cyber café found her password, email and 2FA changed the next morning

## Problem
A travel-booking site keeps customers logged in for 30 days. A customer
booked a ticket on a cyber café PC and closed the browser tab without logging
out. The next person at that PC opened the site, landed in her account, and
from the settings page changed her password, changed the login email to his
own address and switched off two-factor login. None of those forms asked for
the current password. When the owner tried to log in she had no password, no
reset email (it went to the new address) and no 2FA prompt to stop him;
support needed several days of identity checks to hand the account back,
while saved cards and loyalty points were used for bookings.

## Root cause
**Missing re-authentication for critical changes (CWE-620, CWE-306).** The
settings handlers asked only "is there a valid session?". A session proves
that *someone* logged in at some point, not that the person at the keyboard
now is the owner. Session cookies are routinely exposed (shared or stolen
devices, malware, a coworker's unlocked laptop), and those three actions turn
a temporary session into permanent account ownership.

Related but different: 007 revokes sessions after a password reset, 020
rotates the session at login, and 040 stops a changed email from staying
"verified". None of them stop the cookie holder from making the change.

## Solution
`solution.py` keeps `naive_change_password` / `naive_change_email` and adds:

- **`auth_time` in the session,** set only by a full login or a successful
  password confirmation. Ordinary requests update `last_seen`, never
  `auth_time`, so keeping a tab open does not count as proof.
- **`require_step_up`** guards `change_password`, `change_email` and
  `disable_mfa`. It passes when the current password is supplied and correct
  (and then refreshes `auth_time`), or when `auth_time` is within
  `REAUTH_WINDOW_SECONDS` = 5 minutes. An `auth_time` in the future is
  rejected.
- **Failed confirmations are limited:** after `MAX_REAUTH_FAILURES` = 5 wrong
  passwords the session is revoked, so the settings page cannot be used to
  guess the password.
- The session must belong to the account being changed.
- Passwords use salted PBKDF2-SHA256 and `hmac.compare_digest`.

The tests use a fake clock: a cookie reused two hours after login is refused
for all three actions, the current password or a fresh re-auth unlocks them,
the 5-minute boundary is inclusive and expires one second later, 30 minutes
of activity does not extend it, and five wrong passwords end the session.

## Trade-offs
- One extra password prompt for sensitive changes. Five minutes lets a user
  change several settings in one go; shorter windows are safer but annoy.
- Users who signed in with SSO or passkeys have no password to type; step-up
  must then re-run that login (OIDC `max_age`/`prompt=login`, a WebAuthn
  assertion) and use the provider's `auth_time`.
- Step-up stops the cookie thief from *keeping* the account; also email the
  old address on every change with a "this wasn't me" link, and offer
  "log out of all devices".
- Revoking the session on repeated failures can log out a real user who
  mistypes five times; they simply log in again. The counter is per
  session, so keep per-account login throttling (018) as well.

## Run
```bash
python -m unittest -v test_solution.py
```
