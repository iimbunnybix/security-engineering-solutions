# 029 · The login rate limiter and admin IP allowlist were bypassed by sending a fake X-Forwarded-For header

## Problem
A SaaS HR platform sits behind a cloud load balancer and an ingress proxy.
Login allows 5 failed passwords per client IP per 15 minutes, and the admin
panel is reachable only from the office VPN range (`172.16.0.0/12`). During
a password-spraying campaign the security team saw the limiter block
almost nothing: the failed-login dashboard showed the attempts spread over
tens of thousands of "client IPs", each used once or twice, while the load
balancer's access logs showed them coming from a handful of real addresses.
A week later a pentester reached the admin login page from home just by
adding `X-Forwarded-For: 172.16.4.20`. Account takeovers from the spray had
to be reported to customers, and the allowlist could no longer count as a
control in the SOC 2 audit.

## Root cause
The app took the client IP as the **left-most** `X-Forwarded-For` entry.
Proxies *append* the address they received the connection from; they do not
remove what the client already sent. So the left-most entry is whatever the
client chose to write, and only the entries added by our own proxies (the
right-hand end) can be believed. `ReproduceProblem` shows 1,000 out of 1,000
wrong-password attempts allowed when each request carries a random
spoofed IP, and a spoofed VPN address passing the admin allowlist.

## Solution
`trusted_client_ip(peer, headers, trusted_proxies)`:

1. Start from the **TCP peer address**, which the client cannot fake.
2. While the current address is in the configured proxy CIDRs
   (`ipaddress.ip_network`, IPv4 and IPv6), step to the right-most unused
   `X-Forwarded-For` entry: that is who connected to that proxy.
3. Stop at the first address that is **not** one of our proxies. That is
   the client. Anything further left was written by the client.
4. A direct connection from outside ignores the header completely. An
   unparseable entry stops the walk instead of guessing past it.

The limiter and the allowlist use this function. With it, the same spoofing
attacker gets exactly 5 attempts (`MAX_FAILURES_PER_IP`), other clients are
unaffected, and a spoofed VPN address is refused while a real VPN client
still gets in.

## Trade-offs
- The trusted-proxy list must match the real topology. Too narrow (missing
  the ingress hop) and every user looks like the proxy and shares one
  budget; too wide (e.g. trusting all of `0.0.0.0/0` or a CDN range other
  tenants can use) and spoofing works again.
- Behind a CDN, trust its published ranges or use the CDN's own client-IP
  header, and make sure the origin is not reachable directly, otherwise a
  client can connect to the origin and pretend to be the CDN.
- The standard `Forwarded` header (RFC 7239) has the same rule and needs the
  same right-to-left walk; this example handles only `X-Forwarded-For`.
- Per-IP limits still do not stop attackers with many real IPs (botnets,
  residential proxies). Keep per-account limits and breached-password checks
  as well (see problem 018).
- An IP allowlist is a weak admin control on its own; require SSO and MFA
  for the admin panel too.

## Run
```bash
python -m unittest -v test_solution.py
```
