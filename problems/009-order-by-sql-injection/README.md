# 009 · A pentester pulled the admin's API token hash out of the product catalog just by changing the "sort by" option

## Problem
An online store's product listing supports `?category=tools&sort=price&dir=asc`.
The team had standardised on parameterised queries and SQL injection was
believed to be impossible. During an annual penetration test, the tester
recovered the hashed API token of the first admin account using nothing but
the public catalog page. Every request looked like normal browsing and
returned HTTP 200, so the WAF and the error-rate alerts saw nothing.

## Root cause
**Placeholders bind values, not identifiers.** `ORDER BY ?` would sort by a
constant string, so the developer formatted the column into the SQL instead:

```python
f"SELECT id FROM products WHERE category = ? ORDER BY {sort} {direction} LIMIT ?"
```

Any SQL expression is valid in `ORDER BY`. The attacker sends

```
sort=(CASE WHEN substr((SELECT token_hash FROM users WHERE id = 1),1,1)='a'
      THEN price ELSE name END)
```

and compares the order of the results with `sort=price`. If they match, the
guess is right. That leaks one character per hit with no error message and no
visible data (boolean-based blind injection). In the reproduction, a
32-character hex hash is recovered completely through `sort` (about 270
requests on average over 200 runs, never more than 2 + 32 × 16 = 514), and
again through the `dir` parameter alone (`dir=, CASE … END`).

## Solution
`SearchParams.parse` + `search_safe` in `solution.py`:

- **Allowlist of sort keys**: the public names `name`, `price`, `newest` map
  to fixed SQL fragments in `SORT_COLUMNS`. User input chooses a dictionary
  key; it is never copied into the query.
- **Direction is an enum** (`asc`/`desc` → `ASC`/`DESC`), with case and
  whitespace normalised.
- **Bounded `limit`**: ASCII digits only (`str.isdigit()` alone also accepts
  `"²"` or Arabic-Indic digits, and `int("²")` raises a 500), 1–100.
- **Everything else stays bound** (`category`, `limit`), and `id` is added as
  a tie-breaker so ordering is stable.
- Invalid input returns **400** with a generic message; it is never "fixed
  up" and passed through.

Against the fixed endpoint the same extraction stops at the first payload
(rejected with 400) and recovers nothing; `' OR '1'='1` in `category` just
matches no rows.

## Trade-offs
- New sort options need a code change. That is intended: each one is a
  reviewed SQL fragment (and usually needs an index anyway).
- Escaping or quoting identifiers (`"col"`) is weaker: it defends against
  this one shape only if done perfectly for that database's dialect. An
  allowlist is simpler and complete.
- ORMs help only if their sort API takes field names from a fixed set;
  passing raw strings to `order_by()`/`text()` reintroduces the bug.
- Defence in depth: least-privilege database users (the catalog role should
  not be able to read `users` at all) would have made this injection
  much less valuable. Also alert on 400 spikes on search parameters.

## Run
```bash
python -m unittest -v test_solution.py
```
