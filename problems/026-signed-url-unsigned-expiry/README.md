# 026 · Invoice download links that "expire after one hour" still worked months later after changing one number in the URL

## Problem
A billing platform emails customers links to their PDF invoices, such as
`/files/invoice-17.pdf?expires=1790003600&sig=...`. The product promise and
the security review both said links expire after one hour. A penetration
tester took a link from an old email, changed `expires` to a timestamp in
2099, and downloaded the invoice. Every link ever sent (in mailboxes,
forwarded emails, ticket systems and chat logs) was effectively permanent,
and invoices contain names, addresses and payment details.

## Root cause
`naive_sign` computed the HMAC over the **path only**. The `expires` value
was in the URL and was checked against the clock, but it was not covered by
the signature, so the server trusted a value the user could freely change.
A signature only protects the fields that are inside the signed message; any
field the verifier relies on but did not sign is attacker-controlled.

## Solution
- **Sign everything the server relies on.** `canonical_string` builds
  `v1\n<method>\n<path>\n<expires>` and the HMAC-SHA256 covers all of it.
  Changing the expiry, the path, or using a GET link for a DELETE all break
  the signature. Paths with a newline are rejected, so the fields cannot be
  shifted to make two different links sign the same string; the `v1` prefix
  lets the format change later without old signatures matching new rules.
- **Parse the query strictly.** Exactly `expires` and `sig`, each exactly
  once. Duplicate parameters (`...&expires=4070908800`) are a classic way to
  make the signer and the verifier read different values; unknown parameters
  are rejected too. `expires` must be plain digits.
- **Verify the signature first, in constant time** (`hmac.compare_digest`),
  then check expiry.
- **Cap the lifetime** at 7 days when signing, so a bug in the caller cannot
  issue an effectively permanent link.

## Trade-offs
- Links still cannot be revoked before they expire. For that, sign a link id
  as well and check it against a revocation list, or use short lifetimes and
  re-issue links from an authenticated page.
- Anyone who has the link can use it until it expires; it is a bearer
  token. Keep lifetimes short and avoid logging full URLs.
- The server and any CDN must agree on the canonical form (encoding of the
  path, parameter order). Cloud providers' signed URLs (S3 SigV4, CloudFront
  signed URLs, GCS V4 signing) define this for you and are preferable when
  the files live there.
- Rotating the HMAC key invalidates all outstanding links unless you keep
  the previous key for one lifetime and include a key id in the link.

## Run
```bash
python -m unittest -v test_solution.py
```
