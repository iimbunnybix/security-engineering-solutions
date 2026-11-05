# 038 · A stranger joined a customer's workspace as admin using a "viewer" invite link the app signed for him

## Problem
A project-management SaaS lets anyone with a company's public "join" page
request a **viewer** invite. The server emails a link such as
`/join?email=...&role=viewer&sig=<hmac>`; admins issue `role=admin` links
from the settings page with the same signer. A security researcher requested
a viewer invite for the "email" `eve@evil.test&role=admin&z=`, then opened
`/join?email=eve@evil.test&role=admin&z=%26role%3Dviewer&sig=<same sig>`.
The signature verified and he became an admin of the workspace, with access
to every project and the billing settings. The same signer protected
password-less login links, so all signed links had to be reissued.

## Root cause
**Ambiguous canonicalisation before signing (CWE-347).** The signed string
was built as

```python
"&".join(f"{key}={value}" for key, value in sorted(params.items()))
```

with no escaping. Different parameter sets can therefore produce the same
string. The requested invite `{email: "eve@evil.test&role=admin&z=", role: "viewer"}`
and the forged `{email: "eve@evil.test", role: "admin", z: "&role=viewer"}`
both encode to `email=eve@evil.test&role=admin&z=&role=viewer`, so one
HMAC is valid for both (reproduced in the tests). HMAC itself was fine; it
faithfully signed an ambiguous message. Two things let the attacker exploit
it: the verifier signed *whatever* parameters arrived (so the extra `z` was
accepted and ignored by the app), and the email was not validated.

## Solution
`issue_invite` / `accept_invite` in `solution.py`:

1. **Injective encoding:** `canonical` writes each field as
   `<len>:<key><len>:<value>`, so no value can spill into another field
   (`ab`/`c` and `a`/`bc` encode differently, tested).
2. **Fixed field set:** only `SIGNED_FIELDS` (`email`, `role`) are signed, and
   `accept_invite` rejects a link with any extra or missing parameter instead
   of ignoring it.
3. **Validate before signing:** emails containing `&`, `=` or spaces are
   refused at issue time.
4. `hmac.compare_digest` for the signature comparison and a 32-byte random key.

Any one of 1 or 2 stops this forgery; doing all of them removes the class of
bug rather than this one payload.

## Trade-offs
- Length-prefixing is easy to get right but is a custom format; JSON with
  sorted keys or a standard token format (signed JWT with a fixed claim set,
  or the platform's signed-cookie library) is equally unambiguous and easier
  for other services to verify.
- Rejecting unknown parameters breaks links that marketing tools decorate
  with `utm_*` tags; if those must pass, strip a known allow-list of tracking
  parameters before verifying instead of signing them.
- Real invites also need an expiry and single use (see problem 012), and the
  role should ideally be stored server-side under an invite id rather than
  carried in the link at all.
- The email regex here is intentionally strict; internationalised addresses
  would need a fuller validator, but must still be canonicalised safely.

## Run
```bash
python -m unittest -v test_solution.py
```
