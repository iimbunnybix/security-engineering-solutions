# 046 · Attackers logged in with 2FA codes their victims had just typed

## Problem
A retail brokerage protected logins with a password plus a 6-digit TOTP code
from an authenticator app. After a phishing campaign, support saw accounts
where the attacker's session began a few seconds after the customer's own
successful login, *with the same 2FA code*. The phishing page relayed the
password and code to the real site; the victim's login went through, and the
attacker replayed the same code moments later. Several accounts had shares
sold and the money moved before the customers noticed.

## Root cause
- **TOTP codes were treated as valid for a time window, not as one-time
  codes.** The verifier accepted any code matching the current 30-second step
  or one step either side (for phone clock drift) and remembered nothing.
  A code for step *N* is therefore accepted from the start of step *N-1* to
  the end of step *N+1*: up to 90 seconds, any number of times. The test
  `test_captured_code_works_until_end_of_next_step` shows a code still working
  49 seconds after it was first used.
- RFC 6238 section 5.2 says a verifier must not accept the second attempt of
  a code after the first successful validation; that check was missing.

## Solution
`TotpVerifier` in `solution.py`:

1. Find which time step (inside the drift window) the submitted code matches,
   comparing in constant time.
2. **Store the last accepted step per user** and accept a code only if its
   step is *strictly greater*. This rejects the same code twice and also an
   older drift-window code once a newer one has been used.
3. Failed attempts do not update the stored step, so a typo does not burn the
   user's current code. Malformed input (not exactly six ASCII digits) is
   rejected before any HMAC work.

`hotp` follows RFC 4226 and is checked against its published test vectors.

## Trade-offs
- Two legitimate logins within the same 30 seconds (two devices at once) now
  need the user to wait for the next code. That is the standard behaviour of
  replay-safe TOTP.
- `last_used_step` must live in shared storage (the user row, or a store with
  an atomic compare-and-set) when several servers verify codes; otherwise a
  replay sent to another server succeeds. Two simultaneous requests also need
  that atomic update to avoid both passing.
- This stops replay, not real-time phishing: a proxy that uses the code
  *before* the victim still wins. Phishing-resistant factors (WebAuthn /
  passkeys, bound to the site's origin) close that gap. Attempt limits for
  guessing codes are covered in problem 028.

## Run
```bash
python -m unittest -v test_solution.py
```
