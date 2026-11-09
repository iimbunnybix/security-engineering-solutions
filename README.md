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
| 013 | [A free-tier user made himself an organisation admin by adding one field to the "edit profile" request](problems/013-mass-assignment-role-escalation) |
| 014 | [Support agents' accounts started closing tickets and issuing refunds on their own after opening one customer's ticket](problems/014-stored-xss-admin-panel) |
| 015 | [Pentesters rebuilt a customer's live API key from response times alone](problems/015-timing-attack-api-key-compare) |
| 016 | [The same ₹50,000 partner payout went out twice, a week after it was approved](problems/016-webhook-signature-replay) |
| 017 | [Signup API stopped responding when a bot submitted a few odd-looking email addresses](problems/017-redos-email-validation) |
| 018 | [Customers reported "new device login" emails they never made, and dozens of accounts were drained of reward points](problems/018-credential-stuffing-login-throttle) |
| 019 | [Bulk-import workers crashed with out-of-memory errors after a customer uploaded a 64 KB ZIP](problems/019-zip-bomb-upload-limits) |
| 020 | [Customers found strangers placing orders from their accounts after logging in from a link in a "support" email](problems/020-session-fixation-login-rotation) |
| 021 | [Opening the admin "customers" CSV export sent customer data to an unknown website](problems/021-csv-formula-injection-export) |
| 022 | [Any website a customer visited could read their account details and API keys](problems/022-cors-origin-reflection-credentials) |
| 023 | [Customer import returned the server's config file contents in the "name" column of the preview](problems/023-xxe-doctype-xml-upload) |
| 024 | [Users received genuine password-reset emails whose link pointed to a stranger's website](problems/024-host-header-password-reset-poisoning) |
| 025 | [The security team's login log showed an "admin login succeeded" that never happened](problems/025-log-injection-forged-entries) |
| 026 | [Invoice download links that "expire after one hour" still worked months later after changing one number in the URL](problems/026-signed-url-unsigned-expiry) |
| 027 | [A read-only reporting token was accepted by the payments admin API and used to issue refunds](problems/027-jwt-audience-confusion-cross-service) |
| 028 | [Accounts with SMS two-factor login were taken over by scripts that guessed the 6-digit code](problems/028-mfa-code-brute-force-attempt-limit) |
| 029 | [The login rate limiter and admin IP allowlist were bypassed by sending a fake X-Forwarded-For header](problems/029-x-forwarded-for-spoofed-client-ip) |
| 030 | [Attackers ran commands on the web servers by sending a crafted "remember me" cookie](problems/030-pickle-remember-me-cookie-rce) |
| 031 | [Attackers signed in to customers' accounts with their own Google login after sending them a "verify your account" link](problems/031-oauth-missing-state-account-linking) |
| 032 | [Ordinary customers opened the refunds admin page by typing /ADMIN/refunds instead of /admin/refunds](problems/032-admin-path-normalization-auth-bypass) |
| 033 | [A spam crew knew exactly which leaked email addresses were real customers before sending them fake "your order is on hold" emails](problems/033-account-enumeration-reset-signup) |
| 034 | [Moderators who clicked a seller's profile picture to enlarge it had their account email changed to the attacker's](problems/034-svg-avatar-upload-stored-xss) |
| 035 | [Customers' login passwords and bearer tokens were readable by anyone with access to the log search tool](problems/035-secrets-leaked-into-request-logs) |
| 036 | [An attacker gave himself admin on the support platform with a token whose key id pointed at the site's stylesheet](problems/036-jwt-kid-header-key-injection) |
| 037 | [A tenant's "order shipped" email printed the platform's webhook signing key instead of a tracking number](problems/037-format-string-template-secret-leak) |
| 038 | [A stranger joined a customer's workspace as admin using a "viewer" invite link the app signed for him](problems/038-ambiguous-signed-params-role-forgery) |
| 039 | [Shoppers became store admins by editing four bytes of an "encrypted" session cookie](problems/039-unauthenticated-encrypted-cookie-bit-flip) |
| 040 | [An outsider showed up in a company's private workspace after changing his profile email to a company address](problems/040-email-change-keeps-verified-flag) |
| 041 | [Every customer's API key worked for an attacker who got hold of an old analytics replica backup](problems/041-plaintext-api-keys-leaked-replica) |
| 042 | [A customer who forgot to log out at a cyber café found her password, email and 2FA changed the next morning](problems/042-stolen-session-password-change-step-up) |
| 043 | [A CSV upload named "orders.csv; curl … | sh" ran the attacker's script on the import worker](problems/043-shell-command-injection-upload-filename) |
<!-- INDEX:END -->

## Run the tests

```bash
python run_tests.py                       # all problems
cd problems/<folder> && python -m unittest -v
```

Requires Python 3.10+. No third-party packages.

## Author

Hrishikesh Jadhav
