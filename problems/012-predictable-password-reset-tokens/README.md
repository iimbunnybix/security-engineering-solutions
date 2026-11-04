# 012 · Attackers reset other users' passwords without ever seeing the reset email

## Problem
A marketplace's "forgot password" flow emails a link like
`/reset?token=<32 hex chars>`. Over a weekend, dozens of seller accounts had
their passwords changed and payout bank details edited. Every victim said they
had not requested a reset, yet the logs showed each reset request followed by
a successful redemption seconds later, from the attacker's IP, without any
access to the victim's mailbox. Payouts for the affected sellers were frozen
for a week while the accounts were recovered.

## Root cause
**The reset token was derived from values the attacker knows.** The code was:

```python
token = md5(email + str(int(time.time()))).hexdigest()
```

It looks random (32 hex characters), but the only unknown is the second the
request was made, and the attacker chooses that moment by clicking "forgot
password" for the victim's email. Trying the timestamps around their own
request takes a handful of guesses: in the reproduction, with the attacker's
clock 2.4 s off, the token is found on the **7th** guess, and any offset within
±5 s takes at most 11. MD5 is not the problem here; any hash of guessable
input is guessable.

Three other weaknesses made it worse: tokens were stored in plaintext (anyone
with database or support-tool access could use them), they never expired, and
they could be redeemed repeatedly.

## Solution
`ResetTokenService` in `solution.py`:

1. **Random tokens from a CSPRNG:** `secrets.token_urlsafe(32)` (256 bits),
   independent of the user, email and time. Two requests in the same second
   for the same user get unrelated tokens.
2. **Store only `SHA-256(token)`.** The raw token exists only in the email.
   A database dump contains hashes that cannot be used as tokens (tested).
   A fast hash is sufficient because the token has 256 bits of entropy; slow
   password hashes are for low-entropy secrets.
3. **Expiry (30 minutes), single use,** and **a new request invalidates the
   previous token** for that user.
4. Lookup by hash, a final `hmac.compare_digest`, and length checks on input.

The tests reproduce the time-guessing attack, the non-expiring/reusable
tokens and the usable database contents, then show that guessing ±30 s of
timestamps fails against the fix, along with expiry at exactly 30 minutes,
single use, invalidation, isolation between users and malformed input.

## Trade-offs
- After a successful reset, also **revoke existing sessions** and notify the
  user by email; otherwise an attacker who already had a session keeps it.
- Rate-limit reset requests per account and per IP: it does not make tokens
  safer but limits email flooding and enumeration.
- Return the same response whether or not the email exists, to avoid account
  enumeration.
- Signed, stateless tokens (an HMAC over user id, expiry and a password-hash
  fingerprint) avoid a table but are harder to revoke individually; the stored
  hash approach is simpler to reason about.
- Short expiry is a balance with email delivery delays; 15–60 minutes is
  typical (OWASP's Forgot Password Cheat Sheet covers the same points).

## Run
```bash
python -m unittest -v test_solution.py
```
