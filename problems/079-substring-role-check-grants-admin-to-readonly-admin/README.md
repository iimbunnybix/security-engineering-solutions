# 079 · A support agent with a read-only role deleted a customer's account from the admin console

## Problem
A SaaS company's internal admin console lets staff look up and manage
customer accounts. Roles come from the company's identity provider as one
claim string such as `"support,readonly-admin"`. Destructive endpoints such
as "delete account" are meant for the `admin` role only.

A new support agent, given `support,readonly-admin` so they could *view*
accounts, deleted a customer's account while cleaning up what they thought
were test records. The audit review then found that every one of the 40
staff with any role containing the letters "admin" (`readonly-admin`,
`billing-admin-viewer`, `sysadmin-trainee`) had full admin rights in the
console, and had for over a year.

## Root cause
The check was `"admin" in user.roles_claim`. On a Python string, `in` is a
**substring** test, not a membership test, so it is true for any claim that
contains the five characters `admin` anywhere. It was written when the only
roles were `support` and `admin`, and kept "working" until new roles were
added. The same bug appears with `roles.includes("admin")` on a string in
JavaScript, `strpos` in PHP and `LIKE '%admin%'` in SQL.

In the reproduction all five lookalike roles (`readonly-admin`,
`billing-admin-viewer`, `notadmin`, `administrator`, `sysadmin-trainee`)
pass the original check, and the read-only user's delete returns `204`.

## Solution
- `parse_roles` splits the claim on commas into a `frozenset` of exact role
  names, trimming spaces and lowercasing (the IdP is inconsistent about
  both) and skipping empty entries.
- Any entry that is not a plain role name (`support;admin`, `support admin`)
  raises `MalformedRoleClaim`, and `has_role` treats that as "no roles": a
  claim we cannot understand fails closed.
- `has_role(user, "admin")` is a set-membership test, so only the exact role
  `admin` passes. The read-only user now gets `403`.

## Trade-offs
- Prefer the IdP sending roles as a JSON array claim; then there is nothing
  to split, but the check must still be `role in list_of_roles` on a real
  list, never on a joined string.
- Lowercasing assumes role names are case-insensitive in your IdP. If two
  roles differ only by case, do not normalise; reject instead.
- Failing closed on a malformed claim can lock out real admins after an IdP
  change; alert on `MalformedRoleClaim` so it is noticed quickly.
- Role names that *contain* privilege words are a smell. Fine-grained
  permissions (`accounts:delete`) checked exactly are easier to audit than
  role names.

## Run
```bash
python -m unittest -v test_solution.py
```
