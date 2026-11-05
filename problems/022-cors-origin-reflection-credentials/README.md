# 022 · Any website a customer visited could read their account details and API keys

## Problem
A developer platform serves its dashboard from `https://app.example.com`
and its account API from `https://api.example.com`. To make the dashboard
work, the API answered every request with the request's own `Origin`
copied into `Access-Control-Allow-Origin` plus
`Access-Control-Allow-Credentials: true`. A bug-bounty report showed a
page on an unrelated domain calling
`fetch("https://api.example.com/v1/me", {credentials: "include"})` and
reading the logged-in visitor's email, plan and API keys. A quick patch
changed the check to `origin.endswith("example.com")`, which the reporter
bypassed the same day by registering `evil-example.com`. A substring
check would have fallen to `example.com.attacker.net`.

## Root cause
CORS is the server telling the browser which *other* sites may read its
responses. Reflecting the Origin with credentials allowed means "every
site may read this user's data". String suffix and substring tests compare
text, not origins: they ignore the scheme, the port and where the
registrable domain actually starts. Trusting `Origin: null` is the same
mistake, since any sandboxed iframe can send it.

## Solution
`CorsPolicy`:

- **Parses** each Origin into `(scheme, host, port)` with `urlsplit` and
  rejects anything that is not exactly `scheme://host[:port]`: paths,
  queries, user info (`https://app.example.com@attacker.test`), surrounding
  spaces, bad ports, non-HTTP schemes and the opaque origin `null`.
- **Compares exact tuples** against an allowlist parsed once at start-up
  (a malformed entry raises immediately). `https://APP.example.com:443`
  matches `https://app.example.com`; `http://` or another port does not.
- **Echoes the canonical allowlisted origin** (never the raw header) with
  `Access-Control-Allow-Credentials: true` only on a match.
- **Always sends `Vary: Origin`**, so a CDN does not cache one origin's
  response and serve it to another.

`browser_lets_page_read_response` models the browser's rule (Allow-Origin
must equal the page origin and credentials must be allowed) so the tests
show the attack working against the naive code and failing against the fix.

## Trade-offs
- Exact origins mean each new front-end (preview deploys, a new
  subdomain) must be added to the allowlist. If you need "all subdomains",
  match on the parsed host with `host == domain or host.endswith("." + domain)`
  and accept that any subdomain takeover then becomes a data leak.
- CORS only controls *reading* responses. Cross-site *writes* with cookies
  still need CSRF protection and `SameSite` cookies (see problem 005).
- Preflight handling (`Access-Control-Allow-Methods/Headers`, `Max-Age`) is
  out of scope here; it should use the same `is_allowed` decision.
- Token-based APIs that do not use cookies can often skip credentials
  entirely and use `Access-Control-Allow-Origin: *` safely.

## Run
```bash
python -m unittest -v test_solution.py
```
