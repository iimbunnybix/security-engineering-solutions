# 068 · Customer-hosted pages on pages.example.com received every visitor's login session

## Problem
A website-builder SaaS runs its dashboard on `app.example.com` and serves
customers' published sites, including their own HTML and JavaScript, from
`pages.example.com`. To let one login work on `api.example.com` too, the
session cookie was set with `Domain=.example.com`. A security researcher
published a demo site on `pages.example.com` that logged the `Cookie`
header of each request and also read `document.cookie` in JavaScript. Any
signed-in customer who opened the demo page handed over a valid dashboard
session, which was enough to edit and take over their sites.

## Root cause
A cookie with a `Domain` attribute is sent to that domain **and every
subdomain of it** (RFC 6265 section 5.1.3, `domain_matches`). With
`Domain=.example.com` (the leading dot is ignored) the browser attached the
session to `pages.example.com`, which serves content the company does not
control. The test shows the naive cookie reaching every one of five
example hosts, including an old `staging` host. The cookie also lacked
`HttpOnly`, so scripts on the page could read it, and `Secure`, so it was
sent over plain HTTP as well.

## Solution
- **Host-only cookie.** No `Domain` attribute: browsers return the cookie
  only to exactly the host that set it (`browser_sends_cookie`), so of the
  four tested hosts only `app.example.com` receives it.
- **`__Host-` name prefix.** Browsers refuse to store a `__Host-` cookie
  unless it was set over HTTPS with `Secure`, has no `Domain`, and has
  `Path=/` (`browser_accepts_host_prefix`). A later code change cannot
  quietly widen it again, and a subdomain cannot plant a cookie with the
  same name.
- **`HttpOnly`** hides it from page JavaScript; **`SameSite=Lax`** stops it
  being sent on cross-site sub-requests.
- **A validator** (`session_cookie_problems`) lists every unsafe attribute
  of a Set-Cookie header; it reports 5 problems for the original header and
  none for the fixed one, so it can run in CI against real responses.

The 19 tests cover domain matching (label boundaries, IP addresses, the
leading dot, case), which hosts receive each cookie, the prefix rules and
the validator.

## Trade-offs
- `api.example.com` no longer gets the cookie. Serve the API under the same
  host (`app.example.com/api`) or give it its own token-based auth; do not
  widen the session cookie.
- The stronger fix is to host user content on a **separate registrable
  domain** (for example `examplepages.com`, as many hosting products do), so
  it is also outside the site for `SameSite`, and cookies set by customer
  pages cannot touch `example.com` at all. Registering such domains on the
  Public Suffix List also stops customer subdomains sharing cookies with
  each other.
- `SameSite=Strict` is safer still but drops the cookie when users follow a
  link to the dashboard from another site, which looks like being logged out.
- The validator only checks headers you feed it; run it against responses
  from every service that sets cookies, not just the login handler.

## Run
```bash
python -m unittest -v test_solution.py
```
