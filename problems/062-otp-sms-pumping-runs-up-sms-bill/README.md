# 062 · The SMS bill for login codes jumped twenty-fold in a weekend, but logins were flat

## Problem
A food-delivery app logs users in with a one-time code sent by SMS. The
`POST /auth/send-code` endpoint is public (the user is not logged in yet) and
each SMS costs the company money. Over one weekend the SMS provider's bill
rose about twenty times above normal while the number of successful logins
did not change, and the provider's dashboard showed messages going to long
runs of consecutive numbers and to destinations the app does not operate in.

This is **SMS pumping** (also called SMS toll fraud or artificially inflated
traffic): fraudsters trigger messages to number ranges where a carrier shares
the termination fee with them. Nobody ever types in a code; the "attack" is
the bill.

## Root cause
The only protection was a per-number limit of 3 codes per hour
(`NaiveOtpSender`). That stops someone spamming one person, but a pumping bot
never repeats a number many times: it walks through thousands of different
numbers in the same range. In the test, a bot sending to 1,000 consecutive
numbers gets 3,000 SMS paid for within one hour, and a number outside the
countries the app serves is sent a code just like any other. The limit was
keyed on the wrong thing for this attack.

## Solution
`OtpSender` checks, in order, before paying for an SMS:

1. **Valid E.164 number** (`+` and 8 to 15 ASCII digits), so formatting
   tricks and non-ASCII digits cannot create "new" numbers.
2. **Country allowlist** (`+91`, `+971`): the app only operates there, so
   there is no reason to pay for messages anywhere else.
3. **Per-number limit** (3 per hour), kept for its original purpose.
4. **Per-range limit**: at most 20 codes per hour to one number block
   (`+91` plus the first 5 national digits, i.e. 100,000 numbers). Real users
   are spread over many blocks; pumping concentrates on a few.
5. **Global hourly budget** (500): a hard ceiling on the bill even if a bot
   spreads its numbers across many ranges.

Rejected requests are not recorded, so junk traffic cannot use up the budget
for real users. In the test, the same 1,000-number attack now gets 20 SMS
instead of 3,000, while 100 real users in different ranges all get codes.

## Trade-offs
- The global budget turns a cost attack into an availability problem: once it
  is used up, real users cannot log in until the window moves. Alert on it,
  and offer a fallback (email code, authenticator app) rather than relying on
  it alone.
- Range and budget numbers must come from your own traffic. A large employer
  or a new city launch can legitimately concentrate users in one block.
- A bot can spread over many ranges in allowed countries; the per-range limit
  slows it but the global budget is what bounds the cost. Add a CAPTCHA or
  device attestation before sending, and per-IP/device limits.
- Providers offer fraud scoring and per-country spend caps; use them too, as
  they see traffic across many customers.
- Counters here are in memory for one process; production needs a shared
  store (e.g. Redis) so all instances share the same limits.

## Run
```bash
python -m unittest -v test_solution.py
```
