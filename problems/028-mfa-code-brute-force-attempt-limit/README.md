# 028 · Accounts with SMS two-factor login were taken over by scripts that guessed the 6-digit code

## Problem
A consumer brokerage app requires a 6-digit SMS code after the password.
After a credential-stuffing wave, support saw customers whose accounts had
been logged into and drained even though "2FA was on". The logs showed the
attacker's script entering the right password, then sending tens of
thousands of `POST /mfa/verify` requests per challenge, about 100 per second,
and starting a fresh challenge whenever the 5-minute code expired. Victims
got a burst of SMS messages they ignored. The second factor that marketing
and the regulator were told protects accounts added only minutes of work.

## Root cause
The verify endpoint had **no attempt limit**: not per challenge, not per
account. A 6-digit code has only 1,000,000 values, and N distinct guesses
hit a random code with probability **N / 1,000,000** (`guess_probability`,
checked against an exhaustive count in the tests). At 100 guesses/s over the
300 s validity window that is 30,000 guesses, a **3%** chance per challenge;
because new challenges were unlimited, 23 challenges give better than even
odds (1 − 0.97²³ ≈ 50.4%). With one challenge and no rate limit, walking
`000000…` reaches the code `734210` used in the test after 734,211 guesses.
The original code also compared with `==` and let a correct code be reused
until it expired.

## Solution
- **Per-challenge cap.** The 5th wrong guess deletes the challenge, so one
  code can be guessed with probability at most 5 / 1,000,000 = 0.0005%. A
  user who makes up to 4 typos still gets in.
- **Per-account cap across challenges.** At most 10 failures per account in
  a rolling 24 h window; after that `start` refuses to send new codes and
  `verify` rejects even the right code. A full brute-force run therefore gets
  10 guesses per day, a 0.001% chance (0.365% over a whole year of
  attempts), instead of near certainty in under an hour.
- **Constant-time compare** with `hmac.compare_digest` after checking the
  input is exactly 6 ASCII digits, so timing does not reveal correct leading
  digits and look-alike digits (e.g. Arabic-Indic) never match.
- **Single use.** A correct code consumes the challenge; it cannot be
  replayed. Expired challenges are rejected and removed.
- Codes come from `secrets.randbelow`, so they are uniformly random.

## Trade-offs
- The account lock is a denial-of-service lever: anyone with the password
  can lock the real user out of MFA for a day. That is still better than a
  takeover, but pair it with alerting, a forced password reset (the password
  is clearly known), and a recovery path through support or backup codes.
- Limits per account do not stop an attacker spreading guesses across many
  accounts; also rate-limit by IP / device and alert on MFA failure spikes.
- For TOTP apps, "single use" means remembering the last accepted time step
  per user so the same code cannot be replayed within its 30 s window
  (RFC 6238 recommends this). This example models server-sent codes.
- SMS codes are also exposed to SIM swap and phishing relays, which attempt
  limits do not address. Prefer WebAuthn/passkeys where possible.
- Failure counts here live in memory. In production they must be shared
  (e.g. Redis with TTLs) so guesses spread across servers are all counted.

## Run
```bash
python -m unittest -v test_solution.py
```
