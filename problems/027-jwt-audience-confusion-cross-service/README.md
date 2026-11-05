# 027 · A read-only reporting token was accepted by the payments admin API and used to issue refunds

## Problem
A fintech runs about a dozen internal services behind one internal token
issuer. Every service receives short-lived HS256 JWTs signed with the same
shared key. A contractor had a token for the read-only reporting service
(`aud: reporting-api`, `scope: reports:read`). While debugging, they sent
that same token to the payments admin API, and it worked: the admin
endpoints for refunds and payout changes answered with 200. A later review
found the reporting token, which is forwarded to dashboards and copied into
notebooks and log lines, could be replayed against any service that shared
the key. The company had to rotate the key, invalidate every session, and
audit months of admin actions.

## Root cause
The payments admin API checked the HMAC signature and `exp`, which proves
only that *our issuer* minted the token and that it is *still fresh*. It
never checked **who the token was minted for**. RFC 7519 defines the `aud`
(audience) claim for exactly this, and says a recipient that does not
identify itself with a value in `aud` must reject the token. With one
signing key shared by many services, a token for the weakest service is a
valid credential for the strongest one. `naive_verify` also accepts tokens
with no `aud` at all.

## Solution
- **Check the audience.** `verify_for_service` requires `aud` to be a
  non-empty string or a non-empty list of strings, and requires this
  service's own identifier (`payments-admin-api`) to be in it, by exact
  string match. Missing, empty, non-string and look-alike values such as
  `payments-admin-api-staging` are rejected.
- **Check the issuer.** `iss` must equal the trusted issuer exactly, so a
  token from another issuer that happens to share the key (for example a
  staging issuer) is rejected too. A missing `iss` is rejected.
- **Keep the existing checks first.** Signature (constant-time
  `hmac.compare_digest`), a fixed `{"alg": "HS256", "typ": "JWT"}` header,
  and an integer `exp` with 30 s clock skew. The claims are only trusted
  after the signature is verified, so editing `aud` in a token breaks it.
- The reporting token still works at the reporting service; only its use
  elsewhere is blocked.

## Trade-offs
- The audience check stops replay across services, but a single shared HMAC
  key still means **every service can mint tokens for every other service**.
  If the reporting service is compromised, its key can sign
  `aud: payments-admin-api`. The stronger fix is asymmetric signing (RS256 /
  EdDSA): only the issuer holds the private key, services hold only the
  public key. Alternatively, use one HMAC key per audience.
- Tokens with a list of audiences are convenient but widen the blast radius
  of a leak. Prefer one audience per token (token exchange, RFC 8693) for
  high-privilege services.
- `aud` says which service may accept the token; it does not replace
  per-endpoint authorization on `scope`/roles. The payments API should also
  require an admin scope.
- Rolling this out breaks callers that relied on the bug. Log
  "would reject" for a while to find them before enforcing.

## Run
```bash
python -m unittest -v test_solution.py
```
