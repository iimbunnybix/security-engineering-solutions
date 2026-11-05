# 032 · Ordinary customers opened the refunds admin page by typing /ADMIN/refunds instead of /admin/refunds

## Problem
An online electronics shop has an internal admin area (`/admin/users`,
`/admin/refunds`) in the same web app as the storefront. Finance noticed
refunds approved by an account that belonged to a regular customer. Access
logs showed that customer requesting `/ADMIN/refunds`, `//admin/refunds` and
`/products/../admin/refunds`, all answered with HTTP 200. Every refund issued
in the affected weeks had to be re-checked by hand and the admin area was put
behind the VPN until the fix shipped.

## Root cause
Two layers looked at **different strings**. The authorization middleware
checked the raw request path:

```python
if raw_path.startswith("/admin") and not user.is_admin:
    return 403
```

The router then normalised the path before looking up the handler: it
percent-decoded `%61` to `a`, collapsed `//`, resolved `.` and `..`, dropped
`;params` and matched case-insensitively. So every one of these is "not
admin" to the middleware but routes to an admin handler
(`ReproduceProblem` checks all of them):

`/ADMIN/users`, `/Admin/refunds`, `//admin/users`, `/./admin/users`,
`/products/../admin/users`, `/%61dmin/users`, `/;x=1/admin/users`,
`/products/..%2fadmin/users`

This class of bug (a security check on a path that differs from the one the
application finally uses) is behind several published framework and proxy
vulnerabilities; it is described as CWE-647 (use of non-canonical URL paths
for authorization decisions).

## Solution
1. **One canonical path.** `canonicalize` produces the path exactly as the
   router will see it, and `safe_handle` passes that same string to the
   authorization check and to `dispatch`. There is no second interpretation
   for an attacker to aim at.
2. **Reject what is ambiguous instead of guessing.** Encoded slash or
   backslash (`%2f`, `%5c`), double encoding (`%25`), null bytes, raw
   backslashes, a `..` that would climb above `/`, and relative paths get
   HTTP 400. Different proxies and frameworks disagree about these, and real
   links never contain them.
3. **Match whole segments.** `is_admin_area` protects `/admin` and
   `/admin/...` but not `/administrators-guide`.

## Trade-offs
- The canonicaliser must mirror the router's rules exactly. If the
  framework changes how it normalises, this code must change too. Better
  still: attach the permission to the route itself (a decorator or route
  metadata checked after routing), so authorization runs on the matched
  route rather than on a string.
- A reverse proxy in front may normalise differently again (for example
  merging slashes or not). Normalise or reject at the edge as well, and
  test the full chain.
- Rejecting `%2f` breaks APIs that put encoded slashes inside a path
  parameter (for example file names). Those should use query parameters or
  a different encoding.
- Deny-by-default (every route needs an explicit permission) catches admin
  pages added outside `/admin`, which a prefix rule cannot.

## Run
```bash
python -m unittest -v test_solution.py
```
