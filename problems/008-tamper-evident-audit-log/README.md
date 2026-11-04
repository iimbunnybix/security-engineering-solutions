# 008 · During an internal investigation, nobody could prove whether the admin audit log had been edited

## Problem
A payments platform records admin actions (role grants, payout-account
changes, bulk data exports) in an `audit_log` table. During an investigation
into an unexplained bulk export of customer data, the log named one admin,
who said they had never run it. The table was writable by the application's
database user, which several engineers and services could use, so nobody
could show whether rows had been edited, removed or inserted. The log could
not be used as evidence, and the external auditor raised it as a finding.

## Root cause
The log had **no integrity protection**. Each row was independent, so
changing the `actor`, deleting a row or inserting a fake one left a table
that looked perfectly valid. `ReproduceUnprovableLog` shows that an edited
actor and a deleted row both pass the only possible check ("rows are
well-formed"). Database permissions alone did not help: the same credentials
that write the log could also rewrite it.

## Solution
**An HMAC hash chain with external checkpoints.**

1. Each entry stores `mac = HMAC-SHA256(key, canonical_json(entry, prev_mac))`.
   Serialization is canonical (sorted keys, fixed separators), so the same
   content always produces the same MAC.
2. Each MAC covers the previous one, so verification walks the chain and
   reports the **first bad sequence number** and why: content modified,
   sequence gap (deleted entry), broken chain (reordered or renumbered), or
   forged entry without the key.
3. The HMAC key lives in a KMS or secret store, *not* in the database, so DB
   access alone cannot produce valid MACs. Tests generate keys at runtime.
4. A chain cannot detect that its **last** entries were removed. The head
   `(seq, mac)` is therefore copied periodically to write-once storage
   (e.g. object storage with an object lock, or a separate logging account).
   Verification checks every checkpoint, which catches truncation, and also
   catches a full rebuild of the chain by someone who *does* hold the key.
5. Each entry has a `key_id`, so keys rotate without re-signing history.

## Trade-offs
- This makes tampering **evident**, not impossible: an attacker can still
  delete the table. Ship entries to an append-only sink as well, and alert on
  verification failures.
- Appends are serialized (each needs the previous MAC). At high volume, use
  one chain per shard or per time window, each anchored by a checkpoint.
- Anything after the last checkpoint is protected only by the key. Checkpoint
  often (e.g. every minute) to shrink that window.
- Asymmetric signatures (Ed25519) or a transparency log let outside parties
  verify without holding a secret, but need a third-party library or service
  beyond the standard library.
- Don't put raw sensitive data into audit details: they are kept for a long
  time and replicated (the example stores only the last 4 digits).

## Run
```bash
python -m unittest -v test_solution.py
```
