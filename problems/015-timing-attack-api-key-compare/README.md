# 015 · Pentesters rebuilt a customer's live API key from response times alone

## Problem
A B2B logistics API authenticates partners with keys of the form
`sk_<8-hex key id>_<32-hex secret>`. The gateway loaded all keys from the
database as plain text and checked each request with `presented == stored`.

During an annual pentest the testers, starting with only a key id (it appears
in dashboards and logs), sent millions of requests from a host in the same
cloud region and averaged the response times per guess. Guesses whose first
character matched took measurably longer, so they fixed that character and
moved to the next. They recovered a partner's full secret and called the
shipments API as that partner. The finding was rated critical: any partner's
data could be read with no credentials at all.

## Root cause
- **Early-exit comparison.** String `==` stops at the first differing
  character, so the work done (and the time taken) grows with the length of
  the matching prefix. That turns one 128-bit secret (16^32 guesses) into 32
  separate 16-way guesses: at most 16 × 32 = 512 distinct guesses, each
  repeated enough times to average out network noise.
- **Comparing the secret itself.** Because the bytes compared were the secret's
  own characters, every bit of timing leaked was a bit of the key.
- **Plain-text storage.** A database dump or a debug log of the key table
  would have handed out working keys directly.

`solution.py` reproduces the attack deterministically: `LeakyComparator`
counts examined characters in place of wall-clock time, and
`recover_secret_by_timing` recovers the whole secret from the original code
(the last character is found by trying all 16 values, since right and wrong
guesses both examine every character).

## Solution
`HashedKeyStore`:

1. **Store a SHA-256 digest of the secret, keyed by key id.** Lookup by key id
   is a dictionary access, not a scan over all keys with `==`.
2. **Compare digests with `hmac.compare_digest`,** whose running time does
   not depend on where the inputs first differ.
3. **Hashing first removes the signal even without constant-time compare:** a
   guess that shares 10 characters of the secret produces an unrelated digest,
   so the matching prefix of the digests says nothing about the secret. The
   tests run the same attack against the fix with the leaky comparator and it
   fails.
4. **Unknown key ids compare against a dummy digest,** so they do the same
   single comparison as a wrong secret for a real key id.

A fast hash (SHA-256) is fine here because API keys are 128-bit random values;
unlike passwords they cannot be guessed from a dictionary, so a slow KDF would
only add latency to every request.

## Trade-offs
- Keys can only be shown once at creation; support can no longer "look up"
  a customer's key. Rotation must issue a new key.
- The key id is public by design; its presence in the dictionary still
  affects timing slightly (hash lookup). That reveals only which key ids
  exist, not secrets. Returning the same error for both cases keeps it to
  timing only.
- Rate limiting and alerting on many failed attempts per key id is still
  needed: constant-time compare stops this attack, not online guessing.
- Alternatives: HMAC the secret with a server-side pepper (so a database leak
  alone cannot even verify guesses), or signed tokens instead of bearer keys.

## Run
```bash
python -m unittest -v test_solution.py
```
