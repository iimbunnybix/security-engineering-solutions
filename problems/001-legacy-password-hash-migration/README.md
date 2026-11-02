# 001 · Leaked user table with unsalted SHA-1 passwords: migrate without forcing 2M resets

## Problem
A pen test showed a legacy `users` table stores `sha1(password)` with no
salt. If this table leaks, ~70% of passwords can be cracked within hours
using precomputed tables and GPUs. Forcing all 2 million users to reset
their passwords would cause a support spike and churn.

## Root cause
- SHA-1 is a *fast* hash, built for checksums, not passwords: GPUs try
  billions per second.
- No salt, so identical passwords share a hash and rainbow tables work.
- Hash comparison used `==`, which leaks timing information.

## Solution
A versioned hash format and a **two-step migration with no user impact**:

1. **Wrap immediately (offline, one batch job):** for every row, store
   `pbkdf2(sha1_hex, new_salt)` tagged `wrapped$`. The weak hashes are gone
   from the database on day one — no user action needed.
2. **Upgrade on login:** when a user logs in successfully, re-hash the plain
   password with a modern format `pbkdf2_sha256$iterations$salt$hash` and
   replace the wrapped value.
3. Iterations are stored per hash, so raising them later (or switching to
   argon2/scrypt) is the same rehash-on-login path.
4. All comparisons use `hmac.compare_digest` (constant time).

Uses only Python's standard library (`hashlib.pbkdf2_hmac`, `secrets`, `hmac`).

## Trade-offs
- PBKDF2 is still GPU-friendly; Argon2id is preferred where a library is
  allowed. The versioned format makes that switch easy.
- High iteration counts add login latency (~tens of ms) — tune per hardware.
- Users who never log in stay "wrapped" (still strong); they can be expired later.

## Run
```bash
python -m unittest -v test_solution.py
```
