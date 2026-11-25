# 073 · Anyone on the internet could download the full customer list from a new "export" link

## Problem
A B2B SaaS company added a "Download customers as CSV" button to its admin
reports page, backed by a new route `GET /api/reports/customers.csv`. A week
later a security researcher reported that the URL, visible in the
front-end JavaScript bundle, returned every customer's name, email and
phone number **without logging in**. Access logs showed the link had also
been fetched by crawlers. The company had to treat it as a data breach:
notify affected customers and its regulator, and audit every other route
for the same mistake.

## Root cause
The router was **default-allow**. A permission was checked only when the
route declared one:

```python
router.add("/api/reports/customers.csv", export_customers)   # permission= forgotten
```

`NaiveRouter.dispatch` skips the whole check when `permission is None`, so
forgetting one keyword argument turned an admin-only report into a public
endpoint. Nothing failed, no test noticed (the happy path for admins still
worked), and code review saw a one-line route addition. This is OWASP
"Broken Function Level Authorization": security depended on every developer
remembering to opt in on every route.

## Solution
`SecureRouter` in `solution.py` makes the safe choice the default:

1. **`access` is a required argument with no default.** Registering a route
   without it raises `TypeError` at startup; an empty or blank rule raises
   `RouteConfigError`. Public routes must say `access=PUBLIC` out loud, and
   "any logged-in user" is `access=AUTHENTICATED`.
2. **Everything else is a permission name**, checked against the user's
   permissions. A misspelled permission (`reports:reed`) denies everyone,
   so typos fail closed instead of open.
3. **Duplicate registrations are rejected**, so a later route cannot quietly
   replace a protected one.
4. **`audit()` lists every route with its rule**, and
   `unapproved_public_routes` is a CI check that fails when a new `PUBLIC`
   route is not on a reviewed allowlist.

The tests reproduce the leak with `NaiveRouter` (anonymous and shopper both
get the export) and show the fixed router answering 401 for anonymous
visitors, 403 for shoppers and 200 only for users with `reports:read`.

## Trade-offs
- Deny-by-default only covers access to the route. Object-level checks
  ("may this user see *this* invoice?", see 006) still belong in the handler
  or data layer.
- Required rules add a little friction for genuinely public routes; the
  explicit `PUBLIC` marker is the point, because it is visible in review.
- Frameworks offer the same idea: a global default permission (for example
  Django REST Framework's `DEFAULT_PERMISSION_CLASSES`) or authentication
  middleware with an explicit allowlist of anonymous paths. Use those rather
  than a custom router when available.
- The CI allowlist must be maintained; treat changes to it like changes to
  firewall rules.

## Run
```bash
python -m unittest -v test_solution.py
```
