# 059 · A customer called "acme" could download payroll files belonging to the customer "acme-labs"

## Problem
A B2B document platform keeps each customer's files in one object store
under `tenants/<tenant>/...`. The download endpoint takes an object key and
checks that the caller may read it before streaming the file. Thousands of
tenants share the bucket.

A security researcher on the `acme` tenant noticed that changing the key in
a download URL from `tenants/acme/invoices/7.pdf` to
`tenants/acme-labs/payroll/2026-10.csv` returned another company's payroll
export. Any tenant whose name is a prefix of another tenant's name (`acme`
and `acme-labs`, `shop` and `shop2`, `nova` and `novatech`) could read that
tenant's files. The finding had to be disclosed to affected customers as a
cross-tenant data exposure.

## Root cause
Authorisation was a string comparison:

```python
object_key.startswith(f"tenants/{tenant}")
```

`"tenants/acme-labs/..."` starts with `"tenants/acme"`, because a string
prefix is not a path prefix: nothing forces the match to end at a `/`. The
same check also accepted `tenants/acme/../acme-labs/...`, which some proxies
and storage SDKs normalise before fetching.

## Solution
`can_read` compares **whole path segments**:

- Split the key on `/` and **reject ambiguous segments** (`..`, `.`, empty
  segments from `//`), backslashes and NUL bytes, so the key can mean only
  one location in every layer that touches it.
- Require `segments[0] == "tenants"` and `segments[1] == tenant` exactly, plus
  at least one segment below the tenant folder.
- Validate the tenant name itself as one plain segment.
- `read_object` raises the same `Forbidden` whether or not another tenant's
  object exists, so keys cannot be probed.

In the tests `acme` can no longer read `acme-labs` files (or the reverse),
while each tenant still reads its own.

## Trade-offs
- Appending a trailing slash to the prefix (`startswith("tenants/acme/")`)
  fixes the main bug in one line, but still accepts `..` segments; segment
  comparison with explicit rejection is stricter.
- Rejecting `//` and `.` may break clients that build keys sloppily; they
  get a clear 403 instead of a silent cross-tenant read.
- Defence in depth: give each tenant its own bucket or IAM-scoped prefix
  (for example S3 access points or per-tenant credentials), so a bug in this
  check alone cannot expose another tenant.
- Use random tenant IDs rather than names in keys; it removes the
  "one name is a prefix of another" situation entirely.

## Run
```bash
python -m unittest -v test_solution.py
```
