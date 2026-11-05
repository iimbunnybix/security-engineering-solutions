# 020 · Customers found strangers placing orders from their accounts after logging in from a link in a "support" email

## Problem
An online store used server-side sessions identified by a `sid` cookie. The
app also accepted the session ID from a `?sid=` URL parameter, a leftover from
an old checkout flow for browsers without cookies. Several customers reported
orders and address changes they never made. Each had clicked a link in a
"customer support" email that pointed at the real store with
`?sid=<value>` appended, and then logged in normally.

The attacker had chosen that `sid` value. Because the store kept the same
session ID through login, once the customer logged in, the attacker's browser,
sending the same `sid`, was logged in as the customer too, with no password
and no MFA prompt involved. This is **session fixation**.

## Root cause
Two flaws together (both reproduced in `ReproduceProblem`):

1. **Session adoption.** `NaiveSessionManager.start` accepted any ID the
   client sent and created a session under it if none existed, so the
   attacker could pick the ID.
2. **No rotation at login.** `login` marked the existing session as
   authenticated and kept its ID. Any ID known before login (planted, or
   simply read from an anonymous session) was just as valid after it.

Getting an ID into a victim's browser does not need a URL parameter: a
cookie set from a compromised or user-controlled subdomain, or an XSS on an
unauthenticated page, works too. So removing `?sid=` alone is not a fix.

## Solution
`SessionManager` makes session IDs something only the server creates and
something that changes with privilege:

- **Strict mode:** an ID the server never issued is ignored and a new one is
  issued instead. Planted IDs never exist in the store.
- **Rotate on every privilege change:** `login`, `step_up` (after MFA or
  re-entering the password) and `logout` all move the session to a fresh
  256-bit random ID and delete the old one. A pre-login ID is worthless after
  login (`test_pre_login_id_is_worthless_after_login`).
- **Carry over only harmless data:** the cart survives login so the user
  experience does not change; logout drops everything so the next person at
  a shared computer gets an empty session.
- `login` on an unknown ID raises instead of silently creating a session.

In a web framework this is the "regenerate session ID on login" call
(for example `request.session.cycle_key()` in Django, which its login helper
already does); the important part is calling it on every privilege change,
including custom SSO and MFA callbacks.

## Trade-offs
- Rotation briefly leaves two IDs in flight: a parallel request still
  carrying the old ID right after login gets an anonymous session. Some
  systems keep the old ID valid for a few seconds as a read-only alias.
- With a shared session store (Redis), write the new key before deleting
  the old one, as `_rotate` does: a crash in between then leaves an extra
  anonymous session to expire, never an authenticated one under the old ID.
- Cookie attributes (`HttpOnly`, `Secure`, `SameSite`, and the `__Host-`
  prefix, which forbids a `Domain` attribute and so blocks subdomains from
  setting it) make planting harder, but they do not replace rotation.
- Signed, stateless session cookies cannot be "deleted" server-side; they
  need rotation plus a server-side revocation list or epoch (problem 007).

## Run
```bash
python -m unittest -v test_solution.py
```
