# 069 · Users clicked "Claim your prize" on another site and found their account deleted

## Problem
A photo-sharing site's settings page has a **Delete account** button that
works with one click for a logged-in user (the confirmation is a second
button in the same spot). Over one weekend, support received dozens of
messages from users whose accounts, photos and paid storage were gone.
Every deletion was a normal, authenticated POST from the user's own browser
and session; there was no sign of stolen passwords.

The users had all followed a link to a "claim your prize" page shared on a
social network. That page loaded the photo site's settings page in an
**invisible iframe** positioned so that the "Claim" and "Confirm" buttons
sat exactly over "Delete account" and its confirmation. Two clicks deleted
the account.

## Root cause
The site sent **no framing policy**, so any other site could embed any page
in a frame (`naive_response_headers`). The session cookie was set with
`SameSite=None` (needed for an embedded upload widget), so the framed page
loaded logged in, and clicks inside the frame are real clicks on our page.
This is **clickjacking**: CSRF tokens do not help, because the request
really is made by our own page, with its own token.

Two details made it worse than "we forgot a header":

- The site already sent a CSP (`default-src 'self'; script-src 'self'`).
  Without a `frame-ancestors` directive, CSP does not restrict framing.
- An older proposal to allow one partner used `X-Frame-Options: ALLOW-FROM
  <origin>`. Current Chrome, Firefox and Safari do not support
  `ALLOW-FROM` and treat the header as absent.

## Solution
`protected_response_headers` is middleware for every HTML response,
including errors and redirects:

1. **`Content-Security-Policy: frame-ancestors 'self'`**, plus any
   explicitly allowed partner origins (`allowed_embedders`). Partners must
   be `https` origins; they are matched by exact scheme, host and port, so
   `http://partner...` or `partner.example.org.evil.test` do not match.
2. The directive is **merged** into an existing CSP (`merge_into_csp`):
   other directives are kept, and a permissive `frame-ancestors *` is
   replaced rather than left next to the new one.
3. **`X-Frame-Options: SAMEORIGIN`** for browsers too old for
   `frame-ancestors`. When both are present, modern browsers use
   `frame-ancestors` and ignore `X-Frame-Options`, so partners still work.

`can_be_framed` implements the browser's decision, so the tests check that
the attacker's page cannot embed the settings page, our own pages and the
partner can, and the legacy header alone also blocks the attacker.

## Trade-offs
- Headers must be on every response. A page served by a different stack
  (a CDN error page, a legacy admin app) is still framable; check headers
  in an end-to-end test or at the edge proxy, not only in one framework.
- Pages that must be embeddable by anyone (a public video player, a
  "share" widget) need a different policy. Keep sensitive actions off those
  pages entirely.
- Sensitive actions should also require something an invisible frame
  cannot supply: re-entering the password, typing the account name, or a
  confirmation email for deletion. Combined with `SameSite=Lax` or `Strict`
  session cookies, a framed page is then not logged in at all.
- `frame-ancestors` cannot be set in a `<meta>` CSP tag; it must be an HTTP
  header.

## Run
```bash
python -m unittest -v test_solution.py
```
