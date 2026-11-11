# 048 · A self-service signup request came back with role "admin" even though the gateway only allows role "user"

## Problem
A B2B SaaS product lets anyone create a trial account with
`POST /signup {"email": ..., "role": "user"}`. An API gateway in front of the
account service enforced the rule "self-service signups may only ask for role
`user`" and then forwarded the request body to the account service unchanged.

A bug-bounty report showed that this body:

```json
{"email": "mallory@example.com", "role": "user", "role": "admin"}
```

passed the gateway and created an **admin** account, with access to every
customer's data in the tenant. The same trick worked with the second key
written as `"role"`, which also bypassed a regex-based WAF rule looking
for the text `"role": "admin"`.

## Root cause
- **Two parsers read the same bytes differently.** RFC 8259 section 4 says
  object names *should* be unique and that parsers differ when they are not.
  The gateway's parser kept the **first** `role` (`user`) and approved the
  request; the account service used Python's `json.loads`, which keeps the
  **last** one (`admin`).
- **The gateway forwarded the raw body**, not the data it had checked, so the
  check and the action were applied to different values.

## Solution
`gateway_signup` in `solution.py`:

1. **Parse strictly.** `strict_loads` passes `object_pairs_hook` to
   `json.loads`. The hook receives every object's key/value pairs, nested
   objects and objects inside lists included, *after* escape sequences are
   decoded, and raises `DuplicateKeyError` on any repeated key. The request is
   answered with 400 and never reaches the backend.
2. **Validate the parsed object** (role must be `user`, email present).
3. **Forward exactly what was validated**, re-serialised with `json.dumps`, so
   the backend cannot see a value the gateway did not check.

The tests show the original gateway creating an admin from both the plain and
the `role` duplicate, and the fixed gateway rejecting both while normal
signups still work.

## Trade-offs
- Strict parsing rejects some requests that used to work (a buggy client that
  sends a key twice). That is the point, but announce it and log rejections
  for a while before enforcing.
- Re-serialising changes the bytes, so it breaks anything that signs the raw
  body (e.g. webhook HMACs). In that case verify the signature first, then
  parse strictly and pass the parsed object along.
- The deeper fix is to not split one decision across two parsers: let the
  account service enforce "only admins may create admins" itself, based on the
  caller's identity. The gateway check is defence in depth.
- Other parser differences exist (large numbers, invalid UTF-8, comments,
  trailing commas); a strict parse on both sides of a trust boundary is the
  general rule.

## Run
```bash
python -m unittest -v test_solution.py
```
