# 057 · Payouts were marked "paid" by webhook calls whose signature header was just "sha256="

## Problem
A marketplace pays sellers through a payment provider. The provider calls
`POST /webhooks/payouts` with a JSON body and an
`X-Signature: sha256=<hex HMAC of the body>` header, and the handler
updates the payout row (`pending` → `paid` / `failed`), which releases the
order to the seller and closes the support ticket. During an audit,
finance found payouts flagged `paid` that the provider's dashboard showed
as `failed`. The access logs showed requests from an unknown IP whose
signature header was exactly `sha256=`, and a few with a single hex
digit. Each forged call could hide a failed payout or make a seller's
balance look settled.

## Root cause
The verifier compared the received signature against the expected one
with a prefix test:

```python
return expected_hex.startswith(received_hex)
```

Every string starts with `""`, so an empty signature always passes. One
correct hex digit also passes, and there are only 16 possible first
digits, so an attacker needs at most 16 tries per body. A follow-up "fix"
switched to `hmac.compare_digest(expected_hex[:len(received_hex)],
received_hex)`. That removed the timing leak but kept the bug: the
comparison length is still chosen by the attacker. The underlying mistake
is letting the *received* value decide how much of the MAC is checked.

## Solution
`verify_webhook` treats the signature as a fixed-size value:

1. `parse_signature_header` requires the `sha256=` scheme, **exactly 64**
   characters and only `0-9a-fA-F`, then decodes to 32 bytes. Short, long
   or non-hex values are rejected before any comparison. (`bytes.fromhex`
   alone is not enough: it silently skips spaces.)
2. The expected HMAC is computed as raw bytes and compared with
   `hmac.compare_digest` over all 32 bytes, so every byte must match and
   the run time does not reveal where the first mismatch is.
3. Any failure raises `InvalidSignature`, which the handler maps to 401.

The tests show the empty and single-digit signatures passing both naive
checks, then being rejected by the fix along with truncated, extended,
bit-flipped, wrong-scheme and wrong-body signatures.

## Trade-offs
- Truncated MACs are a legitimate design (for example HMAC-SHA-256-128 in
  some protocols), but the truncation length must be fixed by the
  verifier, never taken from the request.
- This check proves the body came from someone holding the secret; it
  does not stop replay of a captured, correctly signed request. Combine it
  with a signed timestamp and a replay window (see problem 016).
- Providers that sign with several active secrets during rotation need a
  loop over the candidate secrets, each compared in full.
- Rejecting uppercase hex would be stricter but would break providers
  that send it; accepting both cases does not weaken the check because
  the decoded bytes are compared.

## Run
```bash
python -m unittest -v test_solution.py
```
