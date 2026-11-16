"""Webhook signature check that compares the whole digest, not a prefix.

The payout-status webhook verified ``X-Signature: sha256=<hex>`` with
``expected_hex.startswith(received_hex)``. Every string starts with the empty
string, so a request with ``sha256=`` (or one correct hex digit, a 1-in-16
guess) was accepted and anyone could mark payouts as "paid". A later "fix"
used ``hmac.compare_digest(expected[:len(received)], received)``: constant
time, but still only checks as many characters as the attacker sends.

This module parses the header strictly, requires exactly 32 decoded bytes
and compares them in full with ``hmac.compare_digest``.
"""
from __future__ import annotations

import hashlib
import hmac
import string

SIGNATURE_SCHEME = "sha256="
# SHA-256 output is 32 bytes, i.e. 64 hex characters.
DIGEST_BYTES = hashlib.sha256().digest_size
DIGEST_HEX_LENGTH = DIGEST_BYTES * 2
HEX_DIGITS = frozenset(string.hexdigits)


class InvalidSignature(ValueError):
    """The webhook request must be rejected with HTTP 401."""


def compute_signature_hex(secret: bytes, body: bytes) -> str:
    """HMAC-SHA256 of the raw request body, as lowercase hex."""
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _strip_scheme(header_value: str) -> str:
    """Return the part after 'sha256=' (the naive versions do the same)."""
    if not header_value.startswith(SIGNATURE_SCHEME):
        raise InvalidSignature("signature must start with 'sha256='")
    return header_value[len(SIGNATURE_SCHEME):]


def naive_verify(secret: bytes, body: bytes, header_value: str) -> bool:
    """Original check: accepts any prefix of the right signature, even ''."""
    received_hex = _strip_scheme(header_value)
    expected_hex = compute_signature_hex(secret, body)
    return expected_hex.startswith(received_hex)


def naive_truncated_compare_verify(secret: bytes, body: bytes, header_value: str) -> bool:
    """First "fix": constant-time, but only over len(received) characters."""
    received_hex = _strip_scheme(header_value)
    expected_hex = compute_signature_hex(secret, body)
    return hmac.compare_digest(expected_hex[:len(received_hex)], received_hex)


def parse_signature_header(header_value: str | None) -> bytes:
    """Decode 'sha256=<64 hex chars>' into exactly 32 bytes, or raise.

    Length and alphabet are checked before decoding so a short, long or
    non-hex value is refused outright instead of being partly compared.
    """
    if header_value is None:
        raise InvalidSignature("missing signature header")
    received_hex = _strip_scheme(header_value)
    if len(received_hex) != DIGEST_HEX_LENGTH:
        raise InvalidSignature(f"signature must be {DIGEST_HEX_LENGTH} hex characters")
    # bytes.fromhex would skip spaces, and str.isalnum accepts non-ASCII
    # letters, so check against the exact hex alphabet.
    for character in received_hex:
        if character not in HEX_DIGITS:
            raise InvalidSignature("signature must be hexadecimal")
    return bytes.fromhex(received_hex)


def verify_webhook(secret: bytes, body: bytes, header_value: str | None) -> None:
    """Raise InvalidSignature unless the header carries the full, correct HMAC."""
    received_digest = parse_signature_header(header_value)
    expected_digest = hmac.new(secret, body, hashlib.sha256).digest()
    # Both sides are always 32 bytes here, so compare_digest checks every byte
    # and its run time does not depend on where the first mismatch is.
    if not hmac.compare_digest(expected_digest, received_digest):
        raise InvalidSignature("signature does not match")
