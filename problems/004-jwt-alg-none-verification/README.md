# 004 · Any logged-in user could become admin by editing their own session token

## Problem
An internal admin API authenticates requests with JWTs issued by the
company's auth service. During a pentest, a tester took their own
low-privilege token, changed the header to `{"alg":"none"}`, changed
`"role":"user"` to `"role":"admin"`, removed the signature and sent it. The
API accepted it. The same review found that tokens never expired in
practice: a token copied from a laptop months earlier still worked.

## Root cause
The hand-written verifier let the **token decide how to verify itself**:

- It read `alg` from the attacker-controlled header and, for `none`,
  returned the payload unverified (RFC 7519 defines unsecured JWTs; a
  verifier must never accept them for authentication).
- It never checked `exp`, `nbf`, `iss` or `aud`, so expired tokens and
  tokens minted for a different service were accepted.
- It compared signatures with `!=` (not constant-time).

Both failures are reproduced in the tests against `naive_verify`.

## Solution
`StrictJWTVerifier`:

- **Pins the algorithm server-side** to `HS256`. `none` in any casing,
  `RS256` (algorithm-confusion attacks), `hs256` and `HS512` are all rejected
  before any key is used.
- **Selects the key by `kid`** from a server-held key ring, which supports
  rotation (old and new keys live side by side). Unknown `kid`s, and a missing
  `kid` when several keys exist, are rejected. Keys shorter than 32 bytes
  are refused at startup (RFC 7518 §3.2 requires ≥ 256-bit keys for HS256).
- **Verifies the signature with `hmac.compare_digest`** and only then
  parses the payload.
- **Validates claims**: `exp` and `iat` are required numbers (booleans
  rejected), `nbf` honoured, `iat` in the future rejected, a maximum token
  age (1 h) caps tokens issued with very long `exp`, and `iss`/`aud` must
  match (list audiences supported). A 30-second leeway handles clock skew.
- Rejects malformed input early: wrong segment count, non-base64url
  characters, non-object header or payload, oversized tokens, `crit` headers.

All failures raise a single `InvalidToken` so callers return a uniform 401
without telling the attacker which check failed.

## Trade-offs
- In production, prefer a maintained library (PyJWT, `jwcrypto`) **with
  an explicit `algorithms=["HS256"]` list** plus the same claim checks. This
  module shows exactly what those settings must enforce.
- HS256 means every verifier holds the signing secret. With many services,
  use an asymmetric algorithm (ES256/RS256) so only the auth service can
  mint tokens, and still pin the algorithm per key.
- JWTs can't be revoked before `exp` without server-side state; keep them
  short-lived (minutes) and use refresh tokens or a deny-list for logout and
  compromised accounts.

## Run
```bash
python -m unittest -v test_solution.py
```
