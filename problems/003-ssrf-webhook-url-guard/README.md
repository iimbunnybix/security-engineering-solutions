# 003 · Webhook test button returned the server's cloud credentials to a customer

## Problem
A SaaS product lets customers register a webhook URL and press "Send test
event"; the response body is shown in the UI to help debugging. A security
researcher registered `http://169.254.169.254/latest/meta-data/iam/...` and
the test response contained the temporary IAM credentials of the webhook
worker's instance role. The same feature could reach Redis, internal admin
panels and any service on the VPC.

## Root cause
**Server-side request forgery (SSRF).** The URL check was a string
blocklist (`"169.254.169.254"` and `"localhost"` not in the URL). Every one of
these bypasses it (reproduced in `test_naive_filter_bypasses`):

- `http://2852039166/` and `http://0xa9fea9fe/`: the metadata IP in decimal
  and hex, which `getaddrinfo` happily parses
- `http://127.1/`, `http://[::1]:6379/`: short-form and IPv6 loopback
- `http://evil-rebind.example/`: an attacker-owned hostname whose DNS
  record points at `10.0.0.5`

Also, the HTTP client followed redirects, so even a "safe" public URL could
`302` to the metadata endpoint.

## Solution
`WebhookURLValidator` decides on **where the request will actually go**,
not on what the URL string looks like:

1. **Allow-list** scheme (`https`) and port (`443`); reject credentials in
   the URL (`user@host` confusion), control characters (header injection)
   and internal names (`localhost`, `*.internal`, `*.local`).
2. **Resolve the host once** and reject if **any** returned address is not
   public: private, loopback, link-local (metadata), CGNAT `100.64/10`,
   multicast, reserved, unspecified, IPv6 ULA, and IPv4-mapped / 6to4 IPv6
   forms are unwrapped and checked as IPv4.
3. **Pin the vetted IP**: the caller connects to `target.ip` and sends
   `target.host` as Host/SNI, so a DNS answer that changes between check
   and connect (DNS rebinding) cannot redirect the request.
4. **Redirects** are handled manually: each `Location` is resolved against
   the current URL and fully re-validated, with a hop limit.

Tests cover every bypass above (using the real resolver for numeric
encodings, which needs no network), mixed public/private DNS answers,
redirect to metadata, redirect loops and a legitimate redirect.

## Trade-offs
- Defence in depth still matters: run webhook workers in a network segment
  with egress only to the internet, and require IMDSv2 (session-token
  metadata) so a single bug doesn't leak credentials.
- Don't return the remote response body to users; status code and timing
  are enough for debugging and leak far less.
- Pinning the IP means you need a client that lets you connect to an IP
  while verifying TLS for the hostname (e.g. `SSLContext.wrap_socket(sock,
  server_hostname=host)` on a socket opened to the IP, or an egress proxy that applies the same rules).
- Blocking all private ranges breaks customers who legitimately want
  webhooks into their own VPN; handle those with explicit, per-tenant
  allow-lists rather than loosening the default.

## Run
```bash
python -m unittest -v test_solution.py
```
