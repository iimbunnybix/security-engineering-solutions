# 031 · Attackers signed in to customers' accounts with their own Google login after sending them a "verify your account" link

## Problem
A personal-finance web app lets logged-in users press "Connect Google" so
they can later use "Sign in with Google". Support received several reports
from users who saw unfamiliar budgets edited and payees added. Each affected
account had a Google identity linked that the owner did not recognise. All of
those users had clicked a link in a "verify your account" email shortly
before. The app had to unlink every Google identity, force password resets
for linked accounts and disable the feature while it was fixed.

## Root cause
The OAuth callback (`original_link_callback`) took the `code` from the URL,
exchanged it, and linked the returned identity to **whoever was logged in in
that browser**. Nothing tied the code to the browser that started the flow,
because the app never sent or checked the OAuth `state` parameter (RFC 6749
section 10.12 calls this out as CSRF against the redirect URI).

The attacker approved the consent screen with their own Google account,
stopped before the callback, and mailed the callback URL (with their code) to
victims. A victim who was logged in opened it, and the attacker's Google
identity was linked to the victim's account. `ReproduceProblem` shows the
attacker then using "Sign in with Google" and landing in the victim's account.

## Solution
- `start_link_flow` creates a random 256-bit `state`
  (`secrets.token_urlsafe`), stores it **server-side in the session** with a
  10-minute expiry, and puts it in the authorize URL.
- `safe_link_callback` checks the returned `state` **before** exchanging the
  code: it must match one this session issued (compared with
  `hmac.compare_digest`), it is removed on first use, and it must not have
  expired. An attacker cannot read the victim's state, and a state from the
  attacker's own session is not in the victim's session, so the planted
  callback is refused and the attacker's code is never exchanged.
- Several pending states are allowed so two tabs both work; expired ones are
  dropped when a new flow starts.
- An identity already linked to another account is refused instead of being
  moved silently.

## Trade-offs
- `state` only protects if it lives in something the attacker cannot set in
  the victim's browser: a server-side session or a signed, `SameSite` cookie.
  A state the server does not remember (for example, any non-empty value) is
  no protection.
- PKCE (RFC 7636) also binds the code to the client that started the flow and
  protects against stolen codes; current OAuth security guidance (RFC 9700)
  recommends using it as well. Many providers support it; this demo checks
  `state` because that is what the original bug was missing.
- For OpenID Connect sign-in, also send and check a `nonce` in the ID token.
- Linking a new sign-in method to an account is sensitive: asking for the
  password or a second factor first, and emailing the owner afterwards,
  limits the damage of any future bug in this flow.

## Run
```bash
python -m unittest -v test_solution.py
```
