# 041 · Every customer's API key worked for an attacker who got hold of an old analytics replica backup

## Problem
A payments-reporting SaaS gives each merchant API keys for its REST API. The
keys lived in an `api_keys` table with a `key` column holding the full key,
and the gateway authenticated requests with
`SELECT customer FROM api_keys WHERE key = ?`.

The data team ran a read-only replica of the main database for dashboards,
with nightly snapshots copied to an object-storage bucket. A misconfigured
bucket policy exposed one of those snapshots. Within days the API logs
showed one cloud IP range pulling settlement reports for hundreds of
merchants, each with that merchant's own valid key. Nothing in the
production database had been breached: a "read-only" copy was enough,
because the column it copied *was* the credential. Every key had to be
rotated at once, which broke every merchant integration for a day.

## Root cause
- **The credential was stored as itself (CWE-256 / CWE-312).** Reading the
  table is equivalent to holding every key. Replicas, backups, ETL exports,
  debug logs of the row and support tooling all inherit full API access.
- **"Read-only" does not mean harmless.** Access controls protected writes
  to production, but read access to any copy of the data was effectively
  write access to every customer account via the API.
- **No public handle.** Because the only identifier was the key itself,
  support and the dashboard had to show or search on the full key, so it
  ended up in more places.

## Solution
`solution.py` keeps the original `NaiveKeyTable` and adds `HashedKeyStore`:

1. **Key format `dk_<prefix>_<secret>`** built with `secrets`: a 12-hex
   (48-bit) prefix that is *not* secret, and a 64-hex (256-bit) secret.
2. **Store only `prefix`, `customer` and `HMAC-SHA256(pepper, full_key)`.**
   The pepper is 32+ random bytes held by the application (environment,
   secrets manager or KMS), never in the database. A leaked row contains no
   key, and without the pepper the attacker cannot even check guesses
   offline. Because the secret is 256 random bits, a fast keyed hash is
   enough; a slow password KDF would only add latency to every request.
3. **Look up by prefix, compare with `hmac.compare_digest`.** An unknown
   prefix is compared against a dummy HMAC so both paths run one comparison.
4. **Show the full key once.** `create_key` returns it in `IssuedKey`; after
   that the dashboard (`display_keys`) shows `dk_<prefix>_…`, and support
   revokes by prefix.
5. **Prefix collisions are regenerated, never overwritten,** and
   `import_plaintext_key` refuses a prefix already in use.
6. **Migration.** `migrate_plaintext_table` hashes each legacy key (so
   merchants keep working keys) and deletes the plain-text row.

Problem 015 covers the *timing* side of comparing keys; this one is about
what a copy of the key table is worth to an attacker.

## Trade-offs
- Lost keys cannot be recovered, only replaced. Merchants must save the key
  when it is shown; plan UI and docs for that.
- The pepper becomes a critical secret: losing it invalidates every key, and
  rotating it means storing a pepper version per row and re-hashing on next
  successful use (or re-issuing keys). Keep it out of the same backups as the
  database, or it protects nothing.
- Migration only helps going forward. Keys that already sat in plain text in
  old backups must be treated as exposed and rotated anyway; also purge or
  re-encrypt those backups.
- The prefix is visible in logs and the dashboard by design; it reveals
  which key was used, not how to use it.
- Signed tokens or mTLS remove shared secrets from the server entirely, at
  the cost of more client complexity.

## Run
```bash
python -m unittest -v test_solution.py
```
