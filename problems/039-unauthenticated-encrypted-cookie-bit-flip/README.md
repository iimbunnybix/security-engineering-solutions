# 039 · Shoppers became store admins by editing four bytes of an "encrypted" session cookie

## Problem
An online shop keeps the session in a cookie instead of a server-side
store. To stop users reading it, the team encrypted the cookie
(`uid=1042;role=user`) with a stream cipher (CTR mode) and one key shared by
all web servers. A bug-bounty hunter noticed the cookie length changed with
the user id, guessed the format, and changed `role=user` to `role=root`
without ever learning the key. He reached the admin panel: order exports with
customer addresses, refunds and discount codes. Every session had to be
invalidated and the key rotated.

## Root cause
**Encryption without integrity (malleable ciphertext, CWE-353 / CWE-649).**
In CTR and other stream modes, `ciphertext = plaintext XOR keystream`. If an
attacker XORs `"user" XOR "root"` into bytes 14-17 of his own cookie, the
server decrypts `role=root`. Nothing checked that the cookie was the one the
server produced. A fixed nonce made it worse: two cookies XORed together
cancel the keystream and give `plaintext1 XOR plaintext2`.
Encryption gives confidentiality, not authenticity.

## Solution
`solution.py` keeps the original `naive_seal` / `naive_open` and adds
`seal` / `open_sealed`, which use **encrypt-then-MAC**:

- A fresh 16-byte random nonce per cookie, so no two cookies share a keystream.
- A separate MAC key and an HMAC-SHA256 tag over `nonce || ciphertext`.
- `open_sealed` checks the length, then compares the tag with
  `hmac.compare_digest` **before decrypting or parsing anything**. Any
  modified, truncated or foreign cookie raises `InvalidCookie`.

The tests show the original attack working (user to root with no key, and the
fixed-nonce XOR leak), then show that the fix rejects the same edit, every
single-bit change across all 66 bytes of a sealed cookie, truncations and a
cookie made with another MAC key.

The keystream is HMAC-SHA256 in counter mode only so the example needs no
third-party package.

## Trade-offs
- In production use an AEAD from a vetted library (AES-GCM or
  ChaCha20-Poly1305, e.g. `cryptography`'s `AESGCM` or Fernet), not a
  home-made construction. AEADs do encryption and authentication in one step.
- If the cookie does not need to be secret, a signed cookie (HMAC only) is
  simpler; see problem 030.
- A sealed cookie still cannot be revoked before it expires; add an expiry
  inside the sealed data and a server-side session version for logout.
- Sealing adds 48 bytes (nonce + tag) to every cookie.
- Random 16-byte nonces are safe for this construction; AES-GCM's 12-byte
  random nonces need key rotation after about 2^32 messages per key.

## Run
```bash
python -m unittest -v test_solution.py
```
