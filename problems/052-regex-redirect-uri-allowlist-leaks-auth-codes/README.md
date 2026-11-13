# 052 · Users who clicked "Sign in with our SSO" on a lookalike site had their accounts taken over

## Problem
A company runs its own OAuth 2.0 authorization server for partner apps.
Partners registered their redirect URIs in a developer portal that accepted
**regular expressions**, so one registration could cover several
environments. Security found authorization codes for real user accounts
being delivered to `appxexample.com`, a domain registered by an attacker.
The attacker sent phishing links that started a normal login on the real
authorization server with `redirect_uri=https://appxexample.com/oauth/callback`;
the server accepted it, the user signed in on the genuine page, and the
code went to the attacker, who exchanged it for tokens.

## Root cause
The server checked `re.match(pattern, redirect_uri)` against each
registered pattern. Three regex mistakes each let a foreign URI through
(all reproduced in `ReproduceProblem`):

| Registered pattern | Accepted attacker URI | Why |
|---|---|---|
| `https://app.example.com/oauth/callback` | `https://appxexample.com/oauth/callback` | `.` matches any character |
| `https://.*.example.com/oauth/callback` | `https://attacker.test/?.example.com/oauth/callback` | `.*` crosses from the host into the query |
| `https://app.example.com/oauth/callback` | `.../oauth/callback/../../logout?next=https://attacker.test` | `re.match` only anchors the start |

The last one chains into any open redirect on the client's own domain.
Regexes are a poor fit for URLs: the authority, path and query have
different rules, and a pattern sees only one flat string.

## Solution
`is_allowed` follows OAuth 2.1 / RFC 9700 (OAuth security BCP): the
redirect URI must **exactly match** a registered URI.
- Both URIs are parsed with `urllib.parse.urlsplit` and compared as
  `(scheme, host, port, path, query)`. Host case and an explicit `:443`
  are normalised; any other difference rejects the request.
- Only `https` is accepted. URIs with userinfo
  (`https://app.example.com@attacker.test/...`) or a fragment are rejected
  outright, and malformed ports return "not allowed" instead of crashing.
- Partners register each environment's callback separately.

## Trade-offs
- Partners lose "one pattern for all preview environments". Offer an API to
  register URIs automatically, or a separate client per environment.
- Native apps on loopback (`http://127.0.0.1:{any port}`) need the RFC 8252
  exception (any port on loopback only); it is not included here.
- Exact matching protects code delivery but not an open redirect *at* the
  registered callback itself. PKCE (RFC 7636) also helps, because a stolen
  code is useless without the verifier held by the real client.

## Run
```bash
python -m unittest -v test_solution.py
```
