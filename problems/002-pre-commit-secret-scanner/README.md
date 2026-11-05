# 002 · A cloud access key was pushed to a public repo and abused within 11 minutes

## Problem
A developer committed a `.env` file containing a cloud access key to a
public GitHub repository. Automated bots scrape new commits for keys; within
11 minutes the key was used to start crypto-mining machines, costing about
₹4.5 lakh before it was revoked. Deleting the file in a later commit did not
help, because the key was still in git history.

## Root cause
Nothing stopped secrets *before* they left the developer's machine. The
`.gitignore` didn't cover `.env.local`, and code review happens after the
push, too late for a public repo.

## Solution
A dependency-free **pre-commit secret scanner**:

- **Known patterns:** cloud access key IDs, GitHub/Slack tokens, private key
  headers, JWTs, and `password=`/`api_key=`-style assignments.
- **Entropy check:** random-looking strings in assignments catch secrets
  that have no known prefix. The limit depends on the alphabet: ≥ 4.0
  bits/char for base64-style values, and ≥ 3.0 for hex values of 16+
  characters, because hex can never exceed log2(16) = 4.0 bits/char.
- **Low noise:** ignores obvious placeholders (`changeme`, `xxxx`, `<your-key>`,
  `${ENV_VAR}`), and supports an inline `# secret-scan: allow` marker and an
  allowlist of fingerprints for reviewed false positives.
- **Redacted output:** findings show `file:line`, rule and a masked value,
  so the scanner never re-leaks what it found into CI logs.
- Exit code 1 blocks the commit (`.git/hooks/pre-commit` or the pre-commit framework).

If a key does leak: **revoke first**, then clean history. Rewriting history
does not un-leak a key that bots have already copied.

## Trade-offs
- Regex + entropy has false positives (hashes, UUIDs) and false negatives
  (short or low-entropy passwords); tools like gitleaks/trufflehog add
  hundreds of rules and live verification.
- Short random tokens (under ~16 characters) cannot be told apart from
  ordinary identifiers by entropy alone: a 12-character random token and
  `localhost:5432` score about the same, so short tokens are only caught by
  the password-name rule or a known prefix. Even for 32-character hex
  keys, roughly 1 in 20,000 random keys scores just under 3.0 and is missed.
- Client-side hooks can be skipped (`--no-verify`); run the same scan in CI
  and enable the hosting platform's push protection as well.

## Run
```bash
python -m unittest -v test_solution.py
python solution.py path/to/file ...      # exit 1 if secrets are found
```
