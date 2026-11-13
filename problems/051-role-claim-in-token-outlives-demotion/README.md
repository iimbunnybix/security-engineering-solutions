# 051 · A contractor demoted to "viewer" deleted customer data three hours later with admin rights

## Problem
An internal admin console for a B2B SaaS product issues signed access tokens
that are valid for 12 hours and carry the user's role. A contractor's admin
role was reduced to `viewer` at the end of their engagement, and their
account was deactivated the same afternoon. Three hours after the demotion
their browser, still holding the morning's token, called the "delete
customer" endpoint and it succeeded. The audit log showed a request
authorized as `admin` from a user whose current role was `viewer`.

## Root cause
Authorization read the **role claim inside the token**. The signature proved
the claim was genuine *when it was issued*, not that it was still true. A
role change or deactivation updated the user store, but nothing connected
already-issued tokens to that change, so each token kept the old rights for
its full lifetime. In the tests, `naive_authorize` allows `delete_customer`
3 hours after the demotion and `read` 11 hours after deactivation.

## Solution
- Each user has a `permission_version` that the store **increments on every
  role change and deactivation**. Tokens carry the version they were issued
  with (`pv`).
- `authorize` verifies signature and expiry, then loads the user and rejects
  the token if the user is missing or inactive, or if `pv` no longer matches.
  The user must sign in again and gets a token with the current role.
- Permissions are computed from the **current role in the store**, never from
  the token's `role` claim, so even a matching token cannot grant more than
  the user has now.

## Trade-offs
- Every request reads the user record. That is usually a cached key lookup,
  but it gives up the "no database call" property of purely self-contained
  tokens. A short cache (seconds) bounds the staleness window instead.
- Bumping the version logs the user out everywhere, even after a promotion.
  That is acceptable for permission changes, which are rare.
- The alternative is short-lived access tokens (5-15 minutes) plus refresh
  tokens checked against the store; staleness is then bounded by the token
  lifetime rather than removed.
- Revoking all tokens of one user is cheap this way; revoking one specific
  stolen token still needs a token ID blocklist or a session store.

## Run
```bash
python -m unittest -v test_solution.py
```
