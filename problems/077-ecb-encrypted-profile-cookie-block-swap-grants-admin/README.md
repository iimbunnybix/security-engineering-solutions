# 077 · Two accounts registered the same afternoon were deleting threads with admin powers nobody gave them

## Problem
A ten-year-old customer forum (about 300,000 accounts) keeps the logged-in
user in a cookie instead of a server-side session. The cookie holds
`email=<email>&role=user&uid=<id>`, encrypted with a block cipher in ECB
mode under one key shared by all web servers. There is no MAC; the team
assumed "encrypted means users can't change it". Each request decrypts the
cookie, loads the account by `email` and checks `role` for the moderation
tools.

During a quarterly access review, the security team found moderation
actions (deleted threads, banned users) made by two accounts registered the
same afternoon, neither ever promoted. The attacker had registered with two
oddly shaped email addresses, glued pieces of the two cookies together, and
been treated as `role=admin` for nine days. Every session was invalidated,
the key rotated and the moderation log rebuilt from backups.

## Root cause
**ECB mode encrypts each 16-byte block independently, and nothing checked
that the cookie was one the server issued (CWE-327 / CWE-353).** The same
plaintext block always encrypts to the same ciphertext block, and any
sequence of valid blocks decrypts without error. So the attacker can:

1. Register with `AAAAAAAAAA` + `admin` + eleven `0x0b` bytes. `email=` plus
   the ten `A`s fill block 0, so block 1 is exactly `admin` with valid PKCS#7
   padding. Only `&` and `=` were stripped, so the control bytes got through.
2. Register with a 20-character email (`eeeeeeeeee@evil.test`), so that
   `email=...&role=` is exactly 32 bytes and `user&uid=1042` starts block 2.
3. Send blocks 0-1 of the second cookie followed by block 1 of the first.
   The server decrypts `email=eeeeeeeeee@evil.test&role=admin`.

The forged cookie is 3 blocks (48 bytes) and needs no key. Problem 039 is
the stream-cipher version (flipping bits in place); here no byte is edited,
whole blocks are moved, and the cookie format let a chosen email line up
`admin` on a block boundary.

## Solution
`solution.py` keeps the legacy `original_issue_cookie` / `original_read_cookie`
and the attack `forge_admin_cookie_by_block_swap`, then adds
`issue_signed_token` / `read_signed_token`:

- **Integrity, not secrecy, is what the cookie needs.** The profile is JSON,
  base64url encoded, followed by an HMAC-SHA256 tag over it, keyed with a
  random 16-byte key (`secrets.token_bytes`).
- `read_signed_token` checks the tag with `hmac.compare_digest` **before**
  decoding or parsing. A spliced token, a payload with another token's tag,
  a token from another key or a malformed token raises `InvalidToken`.
- JSON keeps the email a value: `x@y.z","role":"admin` and the crafted
  `admin`+padding email are stored as plain emails with `role` still `user`.

The tests show the toy cipher round-tripping, ECB repeating equal blocks,
the forgery succeeding, then the fix rejecting a splice of two signed tokens
at every cut point.

The block cipher is a **teaching toy**: a 4-round Feistel network built from
HMAC-SHA256, used only because the standard library has no AES. It shows
ECB's structure and must never protect real data.

## Trade-offs
- **The signed payload is readable.** Base64 is not encryption, so anyone can
  see their own email and uid. That is fine for this cookie. If a cookie must
  also be secret, use an AEAD such as AES-GCM (the `cryptography` package),
  never a mode without authentication.
- **Role in the token goes stale.** A demoted moderator keeps `role` until
  the token is replaced. Better: put only the uid in the token (or use a
  random server-side session id) and load the role from the database on each
  request. Add an expiry claim and rotate signing keys with a key id.
- **Switching keys logs everyone out.** Old ECB cookies must be refused, not
  migrated, because any of them could already be forged.
- **Input validation still matters.** Rejecting control characters in emails
  would have blocked this exact payload, but not the underlying flaw; the
  signature is what makes the cookie trustworthy.

## Run
```bash
python -m unittest -v test_solution.py
```
