# 011 · Customers logged in through a link in a phishing email and were sent to a fake "session expired" page that stole their passwords

## Problem
A SaaS app's login page supports `?next=` so users land back where they were
after signing in. A phishing campaign emailed customers a link to the *real*
login page: `https://app.example.com/login?next=//evil.example/session-expired`.
Victims saw the genuine domain and a valid certificate, logged in
successfully, and were then redirected to a look-alike page saying their
session had expired and asking for the password again. Several accounts were
taken over before the security team traced the campaign. Because the first
hop was the company's own domain, email filters and users both trusted the
link.

## Root cause
**An "is it a local path?" check that does not match how browsers parse
URLs.** The code allowed any `next` value starting with `/`:

```python
if next_url.startswith("/"):
    return redirect(next_url)
```

But browsers treat several such values as links to another host:

- `//evil.example/...` is a scheme-relative URL: same scheme, *different host*;
- `/\evil.example` works too, because browsers treat `\` like `/` in
  http(s) URLs;
- `/<TAB>/evil.example` becomes `//evil.example`, because tabs and newlines
  are removed from URLs.

All three pass the naive check (reproduced in the tests). Values like
`javascript:...` are a related risk if the target is ever rendered as a link.

## Solution
`safe_redirect_target(next_url, allowed_hosts)` in `solution.py`:

1. Rejects missing, oversized (> 2,048 characters) values and any control
   characters, then normalizes the rest the way a browser would (trim
   whitespace and control characters, `\` → `/`).
2. Parses with `urllib.parse.urlsplit` and allows only:
   - a **same-site path**: no scheme, no host, starts with exactly one `/`; or
   - an **https URL on an explicit allow-list of hosts**: exact host match,
     no user-info (`app.example.com@evil.example`), default port only.
3. **Rebuilds** the returned URL from the parsed parts, so the value that was
   validated is exactly what goes into the `Location` header.
4. Anything else falls back to a default page (`/dashboard`) rather than an
   error, so a bad link still ends in a working login.

The tests cover 23 attack values (scheme-relative, backslash, tab/newline,
`https:evil`, `javascript:`/`data:`, user-info, suffix tricks, ports, http
downgrade, NUL bytes, oversized input) and legitimate paths with queries,
fragments, colons and encoded slashes.

## Trade-offs
- The safest design avoids URLs entirely: store the return path server-side
  (in the session) or pass an opaque key into a map of known destinations.
- Allow-listing hosts must be exact; matching with `endswith("example.com")`
  accepts `evilexample.com`. Wildcard subdomains also trust every subdomain,
  including ones a third party may control (subdomain takeover).
- Browser parsing quirks change over time; keep this logic in one shared
  function with tests rather than ad-hoc checks per endpoint (OAuth
  `redirect_uri`, logout redirects, "continue" links in emails).
- Frameworks ship similar helpers (Django's `url_has_allowed_host_and_scheme`);
  prefer them when available.

## Run
```bash
python -m unittest -v test_solution.py
```
