# 036 · An attacker gave himself admin on the support platform with a token whose key id pointed at the site's stylesheet

## Problem
A customer-support SaaS (about 3,000 business customers) authenticates its
API with HS256 JWTs. To make key rotation easy, every token carries a `kid`
(key id) header, and the API loads the matching key from `keys/<kid>` on the
server. A bug-bounty researcher sent a token with
`"kid": "../static/app.css"` and `"role": "admin"`, signed with the bytes of
the public stylesheet at `/static/app.css`, and the API accepted it. With
the same trick he could read any tenant's tickets and change account
settings. A second report a day later used `"kid": "nope"` and an empty
signing key, which also worked. The team pulled admin endpoints offline for
a day, rotated every key and searched the logs for tokens with unusual
`kid` values.

## Root cause
**Key selection controlled by the token (CWE-347, reached through CWE-22 path traversal).** `naive_verify`
trusted the `kid` header, which is attacker-chosen and is read *before* the
signature has been checked:

- `os.path.join(keys_dir, kid)` turned `kid` into a **file path**. `..`
  segments reach any readable file, and the HMAC "key" becomes that file's
  contents. A static asset, a file shipped in the container image, or
  `/dev/null` (empty) all have bytes an attacker can know, so the attacker
  can compute a valid signature.
- A **fallback to a default key** (`DEFAULT_KEY = b""`, added "temporarily"
  during a rotation) meant an *unknown* `kid` was verified with an empty
  key, which is just as predictable.

The tests reproduce three forged admin tokens against the original code:
the stylesheet key, `/dev/null` and an unknown `kid`. The signature check
itself (HMAC-SHA256 with `hmac.compare_digest`) was correct; it was being
run with a key the attacker chose. This is different from 004 (the token's
`alg: none` disabling verification) and 027 (a validly signed token used at
the wrong service).

## Solution
`Keyring` and `verify` in `solution.py`:

1. **Keys come from an in-memory allowlist** loaded at startup (from a
   secret manager, not a directory the token can address). `kid` is only a
   dictionary key; it never reaches the filesystem, a database query or a
   URL.
2. **Strict `kid` format:** a string of 1-64 characters from
   `[A-Za-z0-9_-]`. Lists, numbers, missing values and anything with `/` or
   `.` are rejected before lookup.
3. **Unknown `kid` is rejected.** There is no default key and no "try every
   key" loop; a rotation is done by adding the new key next to the old one
   (the tests accept tokens signed with both during rotation).
4. **The algorithm is pinned per key.** Each `KeyEntry` names its single
   algorithm, and a token whose `alg` differs (including `none`, or HS512
   for an HS256 key) is rejected.
5. **Bad configuration fails at boot:** keys shorter than 32 bytes, empty
   keyrings, duplicate ids and ids with path characters raise `ValueError`
   when the keyring is built.

The payload is parsed only after the signature is valid, and `exp` is
checked against an injected clock.

## Trade-offs
- **Keys must be loaded before use**, so adding a key needs a reload or a
  refresh job instead of dropping a file in a directory. Refresh on a timer
  from the secret manager if rotations must not need a deploy.
- **Shared HMAC keys** mean every verifier can also mint tokens. For many
  services, asymmetric keys (RS256/EdDSA) published as a JWKS are better:
  verifiers hold only public keys, and `kid` selects among them in exactly
  the same allowlisted way. That needs a crypto library outside the
  standard library.
- If keys must live in files, map ids to paths in server config
  (`{"2026-10": "/run/secrets/jwt-2026-10"}`) instead of building the path
  from `kid`.
- The same mistake appears with `jku`/`x5u` headers (key URLs in the
  token). Ignore those headers entirely unless the URL is on a fixed
  allowlist.
- This verifier checks only `exp`; production code must also check
  issuer and audience (see 027) and limit token lifetime.

## Run
```bash
python -m unittest -v test_solution.py
```
