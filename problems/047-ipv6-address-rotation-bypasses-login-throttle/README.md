# 047 · Login throttle never fired for an attacker on IPv6: 1,000 password guesses from one home line went straight through

## Problem
A food-delivery app limited failed logins to 10 per client IP per 15 minutes.
After the company enabled IPv6 on its load balancers, the security team saw a
password-spraying run against customer accounts in which **every single
request came from a different IPv6 address**, all inside one `/64` network
belonging to one residential ISP customer. The throttle never triggered, and
several accounts with weak passwords were taken over and used to order on
stored cards.

The test in this folder models it: one attacker inside `2001:db8:aa:bb::/64`
sends 1,000 wrong guesses in about 8 minutes, each from a new address. The
original throttle lets **all 1,000** through; the fixed one lets **10** through.

## Root cause
- **The throttle key was the address string.** That works for IPv4, where one
  customer usually has one public address (or shares one behind NAT). With
  IPv6 every subscriber is given at least a `/64` network, which is 2^64
  addresses, and an operating system can pick any of them (privacy
  addresses, RFC 8981). Changing address costs the attacker nothing.
- Keying by string also means `2001:db8::1` and `2001:DB8:0:0::1` (the same
  address written two ways) counted as two different clients.

## Solution
`client_key` in `solution.py` decides which bucket a request counts against:

1. Parse the value with the standard `ipaddress` module; anything that is not
   an IP address raises `ValueError` instead of getting a fresh, empty bucket.
2. **IPv4-mapped IPv6 (`::ffff:203.0.113.5`) becomes plain IPv4.** Dual-stack
   sockets report IPv4 clients this way. This must happen before step 3:
   every mapped address lies in `::/64`, so otherwise *all* IPv4 users would
   share one bucket and one attacker could lock everybody out.
3. **IPv6 is keyed by its `/64` network**, the smallest block one subscriber
   normally receives, so rotating addresses inside it hits the same limit.
4. IPv4 stays keyed by the full address.

`LoginThrottle` itself is unchanged in spirit: a sliding 15-minute window of
failure times per key, at most 10 failures.

## Trade-offs
- Many ISPs and cloud providers give a customer a `/56` or `/48` (256 or 65,536
  `/64`s), so a determined attacker can still rotate networks. Add a second,
  looser limit per `/48` (and per account, as in problem 018) rather than
  making the `/64` limit stricter.
- Some mobile carriers and shared offices put many people behind one `/64`, so
  one person's typos count against neighbours. Ten failures per 15 minutes is
  generous enough that this is rare; a "known device" cookie that skips the IP
  limit is the usual remedy.
- The client IP must come from a trusted source (the socket or a proxy header
  you control, see problem 029), or the attacker picks any key they like.
- Counters live in memory; several servers need a shared store with expiry.

## Run
```bash
python -m unittest -v test_solution.py
```
