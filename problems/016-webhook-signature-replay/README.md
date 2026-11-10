# 016 · The same ₹50,000 partner payout went out twice, a week after it was approved

## Problem
A marketplace pays sellers when its payments provider sends a
`payout.approved` webhook. Deliveries were signed with
`HMAC-SHA256(secret, body)` in an `X-Signature` header, and the receiver kept
a table of processed event ids to ignore the provider's retries. A nightly
retention job deleted entries older than 7 days so the table would not grow
forever.

An attacker who had captured a delivery (from a misconfigured logging proxy
that stored full request headers and bodies) re-sent it eight days later. The
signature was still valid, the event id was no longer in the dedup table, and
the seller account he controlled was paid again. Finance found several such
duplicate payouts during month-end reconciliation.

## Root cause
- **The signature did not cover time.** `HMAC(secret, body)` proves the body
  came from the provider, not *when*. A captured delivery is valid forever.
- **Replay protection depended on a table with a retention limit.** Any replay
  older than the retention period looked brand new. No retention value is
  safe, because the signature never expires.
- **The comparison used `!=` on hex strings,** which exits at the first
  differing character (see problem 015 for why that leaks).

## Solution
`WebhookReceiver` with the header format `t=<unix ts>,v1=<sig>[,v1=<sig>]`,
the same scheme Stripe and others publish:

1. **Sign `"<timestamp>.<body>"`.** Changing the timestamp breaks the
   signature, so an attacker cannot refresh an old delivery.
2. **Reject timestamps more than 5 minutes from our clock, in either
   direction.** Future timestamps are also refused so a delivery cannot stay
   "fresh" longer than the window.
3. **Replay cache keyed by event id, kept until `timestamp + tolerance`.**
   That is exactly as long as the timestamp check could still pass. After
   that the freshness check alone rejects the replay, so the cache is small
   and complete: it never needs a retention trade-off. When a re-signed
   retry of an already-seen event arrives with a later timestamp, it is
   rejected and the entry is extended to `retry timestamp + tolerance`, so
   replaying the captured retry later is still caught.
4. **Constant-time comparison** with `hmac.compare_digest`.
5. **Secret rotation:** the receiver accepts a list of active secrets and the
   sender may include one `v1=` signature per secret. Roll out the new secret
   to receivers, switch the sender, then retire the old secret.

The tests reproduce the 8-day replay against the original receiver, check the
boundary second of the window, forged timestamps, tampered bodies, malformed
headers and each step of a rotation. Writing the boundary test caught an
off-by-one in a first draft (the cache entry expired one second before the
timestamp stopped being fresh), which is why that case has its own test.

## Trade-offs
- Receivers need a reasonably synced clock (NTP); skew beyond the tolerance
  rejects legitimate deliveries. Providers retry, and retries are re-signed
  with a new timestamp, so a short window is safe.
- The replay cache here is in memory. With several receiver instances it must
  live in a shared store (for example Redis `SET NX` with an expiry), or a
  replay can hit a different instance.
- This stops replays, not duplicates in general: a provider retry is a new
  delivery of the same event id hours later, so business-level idempotency
  (a unique constraint on event id in the payouts table) is still required.
- Alternatives: mutual TLS between provider and receiver, or fetching the
  event from the provider's API by id instead of trusting the pushed body.

## Run
```bash
python -m unittest -v test_solution.py
```
