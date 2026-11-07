# 040 · An outsider showed up in a company's private workspace after changing his profile email to a company address

## Problem
A team-chat SaaS offers "anyone with a verified `@company` email joins the
company workspace automatically". A
researcher signed up with his own mailbox, clicked the verification link,
then edited his profile email to `cfo@victim-corp.test` and reloaded. He was
auto-joined to Victim Corp's workspace and could read its public channels,
the member directory and shared files. He never received a single email at
the victim's address.

## Root cause
**Verification state not bound to the verified value (CWE-345 / CWE-620).**
The account had one boolean, `email_verified`. Clicking the link set it to
`True`; changing the email replaced the address but left the flag alone, so
"verified" now described an address nobody had proven. Every feature that
trusted `email_verified` (domain auto-join, "log in with email" account
linking, invoice routing) trusted the new, unproven address.

## Solution
`solution.py` keeps `naive_change_email` / `naive_auto_join` and adds:

- **`verified_email`** stores the exact (normalised) address that was proven.
  `is_verified()` is `verified_email == email`, so ANY code path that changes
  the email silently drops verification instead of carrying it over.
- **Pending changes.** `request_email_change` puts the new address in
  `pending_email` and returns a token to send to *that* address. The old
  address stays the account's address until `confirm_email` succeeds.
- **`EmailVerifier`** tokens are random (32 bytes), stored only as SHA-256
  hashes, single-use, expire after 24 hours and are tied to one user and one
  address. A token for a superseded request or for another account fails.

The tests reproduce the auto-join with the naive code, then check that the
fixed flow keeps the old address until the new inbox confirms, refuses
reused, expired, superseded and other-account tokens, and does not join an
unverified account on the company domain.

## Trade-offs
- Users must click a second link when they change email; that is the point,
  but expect support tickets from people who mistype the new address (they
  keep the old one, so they are not locked out).
- Also notify the OLD address about the change with a "this wasn't me" link;
  otherwise an attacker with a stolen session can still move the account.
- Domain auto-join trusts whoever controls the mailbox. Companies that need
  stronger control should use SSO/SCIM instead.
- Normalising with `lower()` treats `Asha@X` and `asha@x` as one address,
  which matches real mail systems for the domain but not strictly for the
  local part; providers that ignore dots or `+tags` need extra rules if you
  use the address for uniqueness.
- In a real database, keep the tokens in a table keyed by the hash with an
  expiry index, and delete them in the same transaction that applies the
  change.

## Run
```bash
python -m unittest -v test_solution.py
```
