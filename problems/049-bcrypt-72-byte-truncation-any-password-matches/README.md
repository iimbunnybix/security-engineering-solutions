# 049 · A pentester logged in to a procurement account with the password "x"

## Problem
A multi-tenant purchasing platform (about 1,800 business tenants, 240,000
staff logins) stores passwords with bcrypt. To "bind the hash to the account"
the login service hashed this string instead of the bare password:

```
<tenant UUID>:<email>:<password>
```

During an annual pentest the tester logged in to
`procurement.notifications@globex-industries.example` with the password `x`,
then with an empty password. Both worked. Approving purchase orders on that
account needs nothing else, so this was rated critical. Shorter emails were
not affected, which is why nobody had noticed.

(Okta published a very similar issue in October 2024: a cache key built with
bcrypt over user id + username + password let users with usernames of 52+
characters sign in without the right password.)

## Root cause
- **bcrypt only uses the first 72 bytes of its input.** Many implementations
  silently ignore the rest instead of failing (some newer library versions
  raise an error for over-long input instead; check what yours does).
- The prefix is 36 (UUID) + 2 (colons) + the email length. For this
  51-character email it is **89 bytes**, so not a single byte of the password
  reached bcrypt: every password produced the same hash. Any email of 34+
  characters had this problem.
- The same limit makes long passphrases weak: two passphrases with the same
  first 72 bytes are the same password to bcrypt.
- C implementations also read the password as a NUL-terminated string, so a
  byte `0x00` ends the input early. This matters for the fix below.

bcrypt is not in Python's standard library, so `bcrypt_like_kdf` in
`solution.py` models exactly that input handling (stop at the first NUL, keep
the first 72 bytes) on top of `hashlib.pbkdf2_hmac`. It uses only 1,000
iterations so the tests run in well under a second; a real system uses bcrypt
itself with cost 12 or more.

## Solution
1. **Pre-hash with a keyed HMAC** (`prehash_password`): compute
   `HMAC-SHA256(pepper, password)` over the *whole* password, of any length.
   The pepper is a random 32-byte secret kept outside the database.
2. **Base64-encode the digest** before giving it to bcrypt. A raw 32-byte
   digest contains a `0x00` byte about 12% of the time, and when it is the
   first byte (1 in 256) bcrypt would hash an empty string. The tests find
   `candidate-password-131` and `candidate-password-380` whose raw digests
   start with `0x00` and show they get *identical* hashes. Base64 gives 44
   printable ASCII bytes: no NUL and always under 72.
3. **Drop the tenant/email prefix.** bcrypt already uses a random per-hash
   salt; the prefix added nothing but the bug.
4. **Migrate on login** (`login`). Old hashes are tagged `legacy`, new ones
   `v2`. A legacy hash cannot be converted without the password, so on the
   next successful login the password is re-hashed with the new scheme. But
   a legacy hash where the prefix left fewer than 12 bytes of the password
   inside the 72-byte window proves almost nothing, so it is **never
   accepted**: the account is flagged `reset_required` and must reset by
   email. With a 36-character UUID that means every email of 23+ characters.

## Trade-offs
- **Losing the pepper locks out every user**, and rotating it means storing a
  pepper id next to each hash and re-hashing at login. Keep it in a secrets
  manager, not in config files or the database.
- Using a *keyed* HMAC, not plain SHA-256, matters: with `bcrypt(sha256(pw))`
  an attacker holding the table can test unsalted SHA-256 hashes leaked from
  other sites against it ("password shucking"). Without the pepper that is
  not possible.
- The forced resets are user-visible. Send them only for affected accounts
  and invalidate those accounts' sessions, since anyone may have logged in.
- A simpler option is to reject passwords over 72 bytes outright. That fixes
  passphrase collisions but not the prefix bug, and annoys password-manager
  users. Argon2id or scrypt have no 72-byte limit and avoid this whole class
  of problem; `hashlib.scrypt` is in the standard library.
- Normalise Unicode (e.g. NFC) before hashing if users type passwords on
  different devices; this example does not.

## Run
```bash
python -m unittest -v test_solution.py
```
