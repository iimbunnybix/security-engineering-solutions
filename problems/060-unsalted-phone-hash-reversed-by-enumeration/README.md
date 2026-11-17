# 060 · An ad partner matched our "anonymised" customer list back to real phone numbers

## Problem
A retailer shared a weekly customer-segment file with an advertising partner
so ads could be targeted to existing customers. To avoid sharing personal
data, each phone number was replaced by its SHA-256 hash, and the file was
described internally as "anonymised".

Months later the partner's own data team showed that they had recovered the
real phone number for every row, and had joined the file with exports from
other retailers that used the same scheme. The company had shared personal
data it had told customers it would not share, which under India's DPDP Act
and the GDPR is still personal data, because hashing without a secret is
pseudonymisation at best and here not even that.

## Root cause
A hash only hides an input that is hard to guess. Indian mobile numbers are
10 digits beginning with 6, 7, 8 or 9: only 4 billion possible values. Anyone
can hash all of them and look each hash up. In plain single-threaded Python
SHA-256 runs at about 2.7 million numbers per second on the machine that ran
these tests, so the whole space takes under half an hour; a GPU does it in
seconds. The test recovers all three customers from one 100,000-number block
in a fraction of a second. And because everyone computes the same hash, files
from different companies join on it trivially.

## Solution
`keyed_pseudonym` uses **HMAC-SHA256 with a secret key** instead of a plain
hash:

- Without the 32-byte key, enumerating every phone number does not help:
  the attacker cannot compute any token to compare with.
- A **separate key per partner** (`new_partner_key`) makes the tokens in two
  partners' files unrelated, so they cannot be joined with each other.
- The same phone still maps to the same token for one partner, so matching
  and frequency counting keep working.
- `normalise_phone` reduces `+91 98200 12345`, `09820012345` and
  `9820012345` to one form first, and rejects non-ASCII digits and anything
  that is not a valid mobile number, so formatting differences do not create
  different tokens.

## Trade-offs
- Security now rests on the key: keep it in a secrets manager, never in the
  export job's config or alongside the data, and rotate it (which changes
  every token) if it leaks.
- If the partner needs to match against *their own* customers, they would
  need the key too, and then they can reverse it again. Use a clean-room or
  private set intersection service instead of shipping tokens.
- A salted slow hash (bcrypt, scrypt) does not fit here: a per-row random
  salt breaks matching, and a shared salt is just a weaker key.
- Pseudonymised data is still personal data under GDPR and DPDP; this fix
  reduces risk, it does not remove the need for consent and a data-sharing
  agreement.

## Run
```bash
python -m unittest -v test_solution.py
```
