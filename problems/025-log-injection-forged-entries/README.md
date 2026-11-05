# 025 · The security team's login log showed an "admin login succeeded" that never happened

## Problem
A SaaS company's login service writes every failed login to a plain-text
auth log. The log is shipped line by line to the SIEM, where a rule alerts on
bursts of failures, and analysts read it during investigations. During a
credential-stuffing attack an analyst found entries like
`... INFO login_succeeded user=admin` with no matching session in the
database. The attacker had been typing them in. The forged lines confused the
investigation for hours, and the "success" lines broke the SIEM's
failure-burst rule, which reset its counter on a success for the same user.

## Root cause
`naive_log_line` builds the line with an f-string and pastes the
**attacker-controlled username** in unchanged. A username such as
`mallory\n2026-11-05T10:00:00Z INFO login_succeeded user=admin` contains a
newline, so one log call produces two lines, and the second is
indistinguishable from a real entry. Log shippers and many viewers also
split on other characters: Python's `splitlines()` (like several log tools)
treats `\r`, `\x0b`, `\x0c`, `\x85`, ` ` and ` ` as line breaks
too, and escape sequences such as `\x1b[2J` can clear or recolour an
analyst's terminal. This is CWE-117, improper output neutralisation for logs.

## Solution
`safe_log_line` keeps the trusted parts (timestamp, level, event name)
outside the user data and writes every untrusted value as `key="escaped"`:

- `\`, `"`, `\n`, `\r`, `\t` become `\\`, `\"`, `\n`, `\r`, `\t`, so a value
  cannot end the line or close its own quotes early (escaping `\` first
  stops an attacker from typing a fake `\n`).
- `\x85`, ` `, ` ` and every other control character (`Cc`) are
  shown as visible code points, e.g. `\x1b`.
- Values over 200 characters are truncated, so one request cannot write
  megabytes into the log.

The tests check that one `login_failed` call always yields exactly one line,
even with every line-break character in the username, and that normal and
non-ASCII usernames stay readable.

## Trade-offs
- Structured JSON logs (`json.dumps` per event) solve the same problem with
  standard escaping and are easier for the SIEM to parse; prefer them for new
  services. The escaping here is for existing text formats.
- Escaping changes how values look; analysts searching for a raw username
  with special characters must search for the escaped form.
- Truncation can cut evidence. Keep the full value elsewhere (a hash, or a
  separate field with a higher limit) if investigations need it.
- Escaping does not make log content trustworthy, only unambiguous. Fields
  such as usernames are still claims by the client, not facts.

## Run
```bash
python -m unittest -v test_solution.py
```
