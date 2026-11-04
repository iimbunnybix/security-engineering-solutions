# 006 · A customer changed one digit in an invoice URL and downloaded another company's invoices

## Problem
A B2B SaaS billing portal lets customers download invoices from
`GET /api/invoices/<id>`. A customer reported, politely, that changing `10452`
to `10451` in the URL showed another company's invoice: name, address,
line items and amounts. Access logs then showed a single account had already
requested ~6,000 consecutive ids over two nights. The breach had to be
disclosed to every affected customer and to the data-protection regulator.

## Root cause
**Broken Object Level Authorization (IDOR)**, #1 on the OWASP API Security
Top 10. The handler checked *authentication* (is there a valid session?) but
not *authorization for this object* (may this user read invoice 10451?). It
ran `SELECT * FROM invoices WHERE id = ?`. Sequential ids made enumeration
trivial: in the reproduction, a `globex` user walking 150 ids receives all
100 of `acme`'s invoices. Nothing alerted on one user getting hundreds of
different objects.

## Solution
- **Scoped lookups only.** `InvoiceRepository.get_for(principal, id)` applies
  the policy as part of the lookup (in SQL: `WHERE id = ? AND tenant_id = ?
  [AND owner_id = ?]`). The unscoped getter is private, and the fixed handler
  never touches it, so the check can't be forgotten in a new endpoint that
  reuses the repository.
- **Deny-by-default policy** (`can_read`): members read their own invoices,
  billing admins read their tenant's, support staff and unknown roles read
  nothing through this path.
- **Uniform 404.** "Belongs to someone else" and "does not exist" return
  identical responses, so the API does not confirm which ids are real.
- **Audit + enumeration detection.** Every denial is logged with user, tenant
  and object id. 20 denials within 60 s flag the account and return 429. In
  the test, a 100-id scan gets zero invoices, 20 × 404 and then 80 × 429,
  while a user making 10 mistakes spread over time is never blocked.

## Trade-offs
- Random UUIDs instead of sequential ids make guessing hard, but they are
  not authorization: ids leak through emails, logs and shared links. Use them
  as defence in depth only.
- Blocking on denial count can lock out a legitimate user with a buggy client,
  and an attacker who knows the threshold can stay just under it. Treat the
  flag as a signal for review, and alert security on it.
- Per-object checks in every handler do not scale across many resource types.
  Centralize them (policy engine such as OPA/Cedar, or row-level security in
  PostgreSQL) and write tests that call every endpoint as a user from another
  tenant.
- Support access is often a real need. Add it through a separate, time-boxed,
  customer-approved grant that is audited, not by widening `can_read`.

## Run
```bash
python -m unittest -v test_solution.py
```
