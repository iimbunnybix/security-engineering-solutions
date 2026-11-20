# 066 · Android users who installed a "coupon" app found strangers logged in to their shopping accounts

## Problem
A retailer's Android app signs users in with OAuth: it opens the login page
in the browser, the user approves, and the authorization server redirects
to `myapp://callback?code=...`. The app then exchanges the code at the token
endpoint. Because anything shipped inside the app can be extracted, it cannot
keep a client secret, so it is registered as a public client and the token endpoint
asks only for the code, `client_id` and `redirect_uri`.

Fraud reports clustered among users who had installed a third-party
"coupon finder" app. That app declared an intent filter for the same
`myapp://` scheme. Android does not reserve custom schemes for one app, so
some redirects went to the coupon app (or users picked it from the chooser).
It sent the code to its operators, who exchanged it for an access token and
refresh token and placed orders with the victims' saved cards.

## Root cause
The authorization code was the only thing needed to get tokens, and a
custom-scheme redirect can be delivered to any app that claims the scheme.
With no client secret, nothing at the token endpoint tied the code to the
app that started the flow. `NaiveAuthServer.exchange` accepts the
intercepted code from the malicious app exactly as it would from the real
one.

## Solution
PKCE (RFC 7636) with the S256 method:

1. **Client:** before each login, `generate_code_verifier` makes a fresh
   verifier from 64 random bytes (86 base64url characters; the RFC allows
   43 to 128 characters from `A-Z a-z 0-9 - . _ ~`). The app sends
   `code_challenge = BASE64URL(SHA256(verifier))` without `=` padding and
   `code_challenge_method=S256`, and keeps the verifier in memory.
2. **Authorization endpoint:** `PkceAuthServer.authorize` refuses a request
   with no challenge, with method `plain` or with no method (RFC 7636
   defaults a missing method to `plain`, where the challenge *is* the
   verifier and an interceptor sees it), or with a challenge that is not 43
   characters. It stores the challenge with a hash of the code.
3. **Token endpoint:** `exchange` removes the code on first use, rejects it
   after 60 seconds, checks `client_id` and `redirect_uri`, requires a
   well-formed `code_verifier`, and compares `S256(verifier)` with the stored
   challenge using `hmac.compare_digest`. The interceptor has the code but
   never saw the verifier, and SHA-256 cannot be reversed from the
   challenge.

`s256_challenge` is checked against the RFC 7636 Appendix B test vector.
The 20 tests cover the interception, the vector, verifier rules, plain or
missing methods, single use, expiry and redirect mismatches.

## Trade-offs
- PKCE stops a malicious app from **redeeming** an intercepted code. It does
  not stop it from starting its own login with its own verifier and
  phishing the user into approving it. Verified HTTPS redirects (Android App
  Links, iOS Universal Links) stop interception itself and should be used
  alongside PKCE.
- Rejecting `plain` breaks very old client libraries that never implemented
  S256; RFC 9700 (OAuth 2.0 Security Best Current Practice) recommends
  S256.
- Burning a code on a failed exchange means a buggy client that sends the
  wrong verifier must restart the login instead of retrying.
- PKCE also protects confidential web clients against code injection, so
  many servers now require it for every client, not only mobile ones.

## Run
```bash
python -m unittest -v test_solution.py
```
