"""Pseudonymise phone numbers with a keyed HMAC, not a plain hash.

A marketing export replaced each customer's phone number with SHA-256(phone)
and called the file "anonymised". Indian mobile numbers are 10 digits starting
with 6-9, only 4 billion values, so anyone can hash every possible number and
look the results up; the partner recovered real phone numbers in hours. This
module uses HMAC-SHA256 with a secret key held only by us, and a separate key
per partner, so the tokens cannot be reversed by enumeration or joined across
partners, while the same phone still maps to the same token for one partner.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable, Iterable, Iterator

# 32 random bytes: the HMAC-SHA256 block is 64 bytes, and 256 bits of key is
# far beyond brute force.
KEY_BYTES = 32
INDIAN_MOBILE_DIGITS = 10
INDIAN_MOBILE_FIRST_DIGITS = "6789"


def normalise_phone(raw_phone: str) -> str:
    """Return the 10-digit national number, so "+91 98200 12345" and "9820012345" match."""
    digits = ""
    for character in raw_phone:
        if character.isascii() and character.isdigit():
            digits += character
        elif character not in " -+()":
            raise ValueError(f"unexpected character in phone number: {character!r}")
    # Strip the country code or a leading trunk 0 when present.
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) != INDIAN_MOBILE_DIGITS or digits[0] not in INDIAN_MOBILE_FIRST_DIGITS:
        raise ValueError("not a valid Indian mobile number")
    return digits


def naive_pseudonym(raw_phone: str) -> str:
    """Original export: unsalted SHA-256 of the phone number."""
    return hashlib.sha256(normalise_phone(raw_phone).encode()).hexdigest()


def new_partner_key() -> bytes:
    """A fresh secret key; stored in the secrets manager, never shipped with the data."""
    return secrets.token_bytes(KEY_BYTES)


def keyed_pseudonym(raw_phone: str, partner_key: bytes) -> str:
    """HMAC-SHA256 token: stable for one partner, useless without the key."""
    if len(partner_key) < KEY_BYTES:
        raise ValueError(f"partner key must be at least {KEY_BYTES} bytes")
    phone = normalise_phone(raw_phone)
    return hmac.new(partner_key, phone.encode(), hashlib.sha256).hexdigest()


def enumerate_block(prefix: str, digits_to_fill: int) -> Iterator[str]:
    """Yield every phone number that starts with prefix, e.g. one operator's block."""
    for suffix in range(10 ** digits_to_fill):
        yield prefix + str(suffix).zfill(digits_to_fill)


def dictionary_attack(tokens: set[str], candidates: Iterable[str],
                      token_function: Callable[[str], str]) -> dict[str, str]:
    """What the partner did: hash every candidate and look it up in the export."""
    recovered: dict[str, str] = {}
    for phone in candidates:
        token = token_function(phone)
        if token in tokens:
            recovered[token] = phone
    return recovered
