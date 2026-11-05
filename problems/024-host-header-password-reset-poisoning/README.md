# 024 · Users received genuine password-reset emails whose link pointed to a stranger's website

## Problem
An online store (about 2 million accounts) sends "forgot password" emails
from its own mail domain. Support received reports of reset emails that
users had not requested, and a handful of accounts were taken over shortly
after their owners clicked the link. The emails were real and correctly
signed, but the link host was `attacker.example` instead of the store's
domain. Taken-over accounts had saved cards and loyalty points.

## Root cause
**Host header poisoning.** The reset handler built the absolute link from
the request: `X-Forwarded-Host` if present, otherwise `Host`. Both headers are
set by the client. The attacker sent `POST /forgot-password` with the
victim's email and `Host: attacker.example` (or a spoofed `X-Forwarded-Host`
that the load balancer passed through). The store generated a valid token for
the victim and emailed `https://attacker.example/reset-password?token=…`.
When the victim clicked, the attacker's server logged the token and used it
on the real site.

`ReproduceProblem` shows both header variants putting the attacker's domain
into the email.

## Solution
`ResetService` removes the header from link building entirely:

1. **Canonical base URL from configuration.** Links are always
   `base_url + /reset-password?token=…`. The base URL is validated at startup
   (must be `https://host` with no path).
2. **Host allowlist.** Requests whose `Host` or `X-Forwarded-Host` is not one
   of our hostnames are refused before a token is created or an email sent.
   Comparison is exact after lower-casing and dropping a default `:443`, so
   look-alikes (`app.shop.example.attacker.example`, other ports, userinfo
   tricks) fail.
3. Tokens are 32 random bytes from `secrets`, stored only as SHA-256 hashes,
   and the endpoint returns the same text whether or not the account exists.

## Trade-offs
- The allowlist must be kept in sync with every real hostname (regional
  domains, staging). A missing entry blocks resets on that domain, which is
  visible and safe, unlike a missing check.
- Ideally the edge proxy also overwrites `X-Forwarded-Host` instead of passing
  the client's value through, and the web framework's own setting (for
  example Django `ALLOWED_HOSTS`) is enabled; this code does not replace that.
- A multi-tenant product with customer domains needs a per-tenant base URL
  looked up from the tenant record, never from the header.
- Short token lifetimes and single use (not shown here) limit the damage if a
  link leaks some other way, such as through referrer logs.

## Run
```bash
python -m unittest -v test_solution.py
```
