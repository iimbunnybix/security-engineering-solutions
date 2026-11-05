# 018 · Customers reported "new device login" emails they never made, and dozens of accounts were drained of reward points

## Problem
A shopping app's `POST /login` accepted an email and password and returned a
session. Overnight the endpoint's traffic jumped sharply. Most requests failed, but
a few percent succeeded, and by morning support had dozens of tickets from
customers whose saved reward points had been redeemed for gift cards. Every
affected customer had reused a password from another site whose user list had
leaked. This is **credential stuffing**: the attacker was not guessing, just
replaying a leaked email/password list against our login as fast as the API
would answer.

The test in this folder models it: 1,000 accounts, a leaked list with one
pair per account, and 24 of those pairs (seeded random, about 2%) still work on
our site. With the original endpoint one IP can try all 1,000 pairs in seconds
and take over all 24 accounts.

## Root cause
- **Failed logins cost the attacker nothing.** There was no counting of failures
  per account or per source, so the only limit was server throughput.
- A first attempt at a fix (locking an account for 24 hours after 5 failures)
  was rejected in review: it lets anyone lock any customer out by typing their
  email five times, which turns a security control into a denial-of-service
  tool.

## Solution
`ThrottledLoginService` in `solution.py`:

1. **Two failure counters:** one per account (stops a botnet hammering one
   account from many IPs) and one per client IP (stops one IP walking through
   many accounts — the usual stuffing pattern).
2. **Exponential backoff, not lockout.** The first 5 failures are free (typos);
   after that each key must wait 1 s, 2 s, 4 s, … capped at 15 minutes. The
   throttle is checked *before* the password, so a throttled attacker learns
   nothing from a correct guess.
3. **Bounded and forgiving.** A success resets both counters, and failures more
   than an hour apart start a fresh count.
4. **Trusted IPs skip the account throttle.** An IP that has logged in to the
   account before is only subject to its own IP counter, so an attacker
   failing on the account from elsewhere cannot lock the owner out. On a new
   IP the owner waits at most the 15-minute cap.

In the seeded simulation an attacker on one IP gets **17 attempts in the first
hour** (5 free, then backoff) and takes over 0 of the 24 vulnerable accounts,
versus 1,000 attempts and 24 takeovers before.

## Trade-offs
- A large botnet with thousands of IPs still gets ~17 attempts/hour **per IP**.
  Per-IP limits slow stuffing, they do not end it. Real defences add breached
  password checks at signup/login (e.g. k-anonymity range queries against a
  breach corpus), MFA or step-up challenges for new devices, and bot detection.
- Trusting by IP is coarse: shared NAT or a mobile carrier can put the attacker
  and the owner on the same IP. A signed "known device" cookie is a better key
  for the trust rule; IP is used here to keep the example small.
- Counters live in memory here. With several API servers they must live in a
  shared store (e.g. Redis with TTLs) so an attacker cannot spread attempts
  across servers.
- Returning `THROTTLED` with a retry time tells the attacker the throttle
  exists; that is acceptable because it does not reveal whether the account
  exists or which password was right.

## Run
```bash
python -m unittest -v test_solution.py
```
