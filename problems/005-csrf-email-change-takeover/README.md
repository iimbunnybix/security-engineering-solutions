# 005 · Users' account emails were changed to attacker addresses after they visited an unrelated website

## Problem
Over one weekend, about 40 customers of an online banking portal reported they
could no longer log in. In each case the account's login email had been
changed to an address the user had never seen, followed by a password reset
to that address. The users had not shared credentials or clicked a phishing
login page. The common factor was a forum post linking to a "coupon" page.

## Root cause
**Cross-Site Request Forgery.** `POST /account/email` authenticated the
caller only by the session cookie. The coupon page contained a hidden form
targeting that URL with `email=attacker@…` and submitted it with JavaScript.
The victim's browser attached the session cookie, and the server could not
tell the forged request from a real one.

The cookie had been set to `SameSite=None` so a partner widget could run in an
iframe, which removed the browser's default `Lax` protection. The test
`test_unprotected_endpoint_accepts_cross_site_form` reproduces the takeover.

## Solution
`CsrfProtection` adds two independent checks to every state-changing request
(`protect(csrf, handler)` wraps a handler):

1. **Origin verification.** `Origin`, or `Referer` when `Origin` is absent or
   `null`, must normalize to one of the app's own origins (scheme, host and
   port compared exactly). Requests with neither header are rejected.
   Look-alikes such as `bank.example.evil.example`, a different port, or
   `http://` are rejected.
2. **Session-bound token.** The server embeds
   `HMAC-SHA256(key, "csrf:" + session_id)` in forms (`csrf_token`) or hands
   it to the SPA for an `X-CSRF-Token` header, and compares it with
   `hmac.compare_digest`. A cross-site page cannot read it, a token from the
   attacker's own session does not match, and no server-side token storage is
   needed.

GET/HEAD/OPTIONS skip the checks, so those methods must never change state.
Also, keep session cookies `SameSite=Lax` (or `Strict`) wherever possible, and
require re-authentication for high-risk changes like the login email.

## Trade-offs
- Origin checks alone would have stopped this attack, but some proxies and
  privacy tools strip `Origin`/`Referer`. Here they fail closed (403), which
  can block a few legitimate users. The token is the second layer.
- The token is valid for the whole session. If the session id rotates on login
  (it should, to prevent session fixation), issue a new token too.
- An XSS bug defeats every CSRF defence: injected script runs on your origin
  and can read the token. CSRF protection does not replace output encoding
  and CSP.
- APIs authenticated with an `Authorization: Bearer` header (not cookies) are
  not exposed to classic CSRF. Don't let such APIs fall back to cookie auth.
- Most frameworks (Django, Rails, Spring Security) ship CSRF middleware.
  Prefer enabling it over writing your own; this module shows what it must do.

## Run
```bash
python -m unittest -v test_solution.py
```
