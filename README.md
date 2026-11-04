# Security Engineering Solutions

Real application-security problems (password storage, secret leaks, auth, input validation), each with root cause, a working Python fix and tests.

Every problem folder has the same structure:

| File | Contents |
|---|---|
| `README.md` | The incident or requirement, root cause, solution and trade-offs |
| `solution.py` | Working implementation (Python standard library only) |
| `test_solution.py` | Tests that reproduce the problem and prove the fix |

## Problems

<!-- INDEX:START -->
| # | Problem |
|---|---|
| 001 | [Leaked user table with unsalted SHA-1 passwords: migrate without forcing 2M resets](problems/001-legacy-password-hash-migration) |
| 002 | [A cloud access key was pushed to a public repo and abused within 11 minutes](problems/002-pre-commit-secret-scanner) |
| 003 | [Webhook test button returned the server's cloud credentials to a customer](problems/003-ssrf-webhook-url-guard) |
| 004 | [Any logged-in user could become admin by editing their own session token](problems/004-jwt-alg-none-verification) |
| 005 | [Users' account emails were changed to attacker addresses after they visited an unrelated website](problems/005-csrf-email-change-takeover) |
| 006 | [A customer changed one digit in an invoice URL and downloaded another company's invoices](problems/006-idor-invoice-download) |
| 007 | [A user reset her password after losing her laptop, and the laptop stayed logged in](problems/007-session-revocation-password-reset) |
| 008 | [During an internal investigation, nobody could prove whether the admin audit log had been edited](problems/008-tamper-evident-audit-log) |
| 009 | [A pentester pulled the admin's API token hash out of the product catalog just by changing the "sort by" option](problems/009-order-by-sql-injection) |
| 010 | [A customer downloaded the server's database password through the "download your export" link](problems/010-path-traversal-file-download) |
| 011 | [Customers logged in through a link in a phishing email and were sent to a fake "session expired" page that stole their passwords](problems/011-open-redirect-after-login) |
| 012 | [Attackers reset other users' passwords without ever seeing the reset email](problems/012-predictable-password-reset-tokens) |
<!-- INDEX:END -->

## Run the tests

```bash
python run_tests.py                       # all problems
cd problems/<folder> && python -m unittest -v
```

Requires Python 3.10+. No third-party packages.

## Author

Hrishikesh Jadhav
