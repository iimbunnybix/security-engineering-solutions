"""Constant-time API key verification with hashed keys looked up by key id.

The original API gateway kept customer API keys in plain text and checked a
presented key with ``==``. String equality stops at the first differing
character, so a request whose guess shares a longer prefix with a real key
takes slightly longer. By measuring that, an attacker can recover a key one
character at a time instead of brute-forcing the whole thing.

The fix stores only a SHA-256 digest of each key's secret, finds the record by
a public key id embedded in the key, and compares digests with
``hmac.compare_digest``. Timing no longer depends on how much of the secret a
guess got right, and a database leak no longer exposes usable keys.
"""
from __future__ import annotations

import hashlib
import hmac
import random
import secrets
from dataclasses import dataclass
from typing import Callable

KEY_PREFIX = "sk"
KEY_ID_HEX_CHARS = 8
SECRET_HEX_CHARS = 32
HEX_ALPHABET = "0123456789abcdef"
# How many fresh key ids create_key tries before giving up. A collision on a
# 32-bit key id is rare, so several in a row means something is broken.
MAX_CREATE_ATTEMPTS = 5

# A comparator takes two values and says whether they are equal.
Comparator = Callable[[object, object], bool]


class LeakyComparator:
    """Early-exit equality that counts how many characters it examined.

    The count stands in for response time: in production each examined
    character costs a few nanoseconds, which an attacker averages over many
    requests. Counting makes the leak deterministic for tests.
    """

    def __init__(self) -> None:
        self.characters_examined = 0
        self.calls = 0

    def __call__(self, left: object, right: object) -> bool:
        self.calls += 1
        if len(left) != len(right):
            return False
        for index in range(len(left)):
            self.characters_examined += 1
            if left[index] != right[index]:
                return False
        return True


def generate_api_key(rng: random.Random | None = None) -> str:
    """Build a key like ``sk_<key id>_<secret>``; the key id is not secret."""
    if rng is None:
        key_id = secrets.token_hex(KEY_ID_HEX_CHARS // 2)
        secret = secrets.token_hex(SECRET_HEX_CHARS // 2)
    else:
        key_id = "".join(rng.choice(HEX_ALPHABET) for _ in range(KEY_ID_HEX_CHARS))
        secret = "".join(rng.choice(HEX_ALPHABET) for _ in range(SECRET_HEX_CHARS))
    return f"{KEY_PREFIX}_{key_id}_{secret}"


def split_api_key(api_key: str) -> tuple[str, str] | None:
    """Return (key_id, secret), or None when the key is not well formed."""
    parts = api_key.split("_")
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        return None
    key_id, secret = parts[1], parts[2]
    if len(key_id) != KEY_ID_HEX_CHARS or len(secret) != SECRET_HEX_CHARS:
        return None
    return key_id, secret


def naive_authenticate(presented_key: str, stored_keys: dict[str, str],
                       comparator: Comparator) -> str | None:
    """ORIGINAL: compare the presented key to every plain-text key with ``==``.

    ``stored_keys`` maps plain-text key -> customer. The comparator is passed
    in so tests can observe how much work each comparison does.
    """
    for stored_key, customer in stored_keys.items():
        if comparator(presented_key, stored_key):
            return customer
    return None


def digest_secret(secret: str) -> bytes:
    """SHA-256 of the secret. Keys are long random values, so a fast hash is
    enough here (unlike passwords, they cannot be guessed from a dictionary)."""
    return hashlib.sha256(secret.encode()).digest()


class DuplicateKeyIdError(ValueError):
    """Raised instead of silently replacing another customer's key."""


@dataclass(frozen=True)
class KeyRecord:
    customer: str
    secret_digest: bytes


class HashedKeyStore:
    """FIX: stores key id -> digest of the secret and compares in constant time."""

    def __init__(self) -> None:
        self._records: dict[str, KeyRecord] = {}
        # Compared against when the key id is unknown, so that path does the
        # same work as a wrong secret for a real key id.
        self._dummy_digest = digest_secret("0" * SECRET_HEX_CHARS)

    def add_key(self, api_key: str, customer: str) -> None:
        """Register a key. Only its digest is kept; the caller shows the key once."""
        parsed = split_api_key(api_key)
        if parsed is None:
            raise ValueError("malformed API key")
        key_id, secret = parsed
        # Key ids are random 32-bit values, so two keys can share one. Writing
        # over the old record would silently break another customer's key.
        if key_id in self._records:
            raise DuplicateKeyIdError(f"key id {key_id} is already in use")
        self._records[key_id] = KeyRecord(customer, digest_secret(secret))

    def create_key(self, customer: str, rng: random.Random | None = None) -> str:
        """Generate and register a new key, retrying when its key id is taken.

        ``rng`` is only for tests; production uses the ``secrets`` module.
        """
        for _attempt in range(MAX_CREATE_ATTEMPTS):
            api_key = generate_api_key(rng)
            try:
                self.add_key(api_key, customer)
            except DuplicateKeyIdError:
                continue
            return api_key
        raise DuplicateKeyIdError(
            f"no free key id after {MAX_CREATE_ATTEMPTS} attempts")

    def stored_values(self) -> list[bytes]:
        """What a database dump would reveal: digests only."""
        return [record.secret_digest for record in self._records.values()]

    def authenticate(self, presented_key: str,
                     comparator: Comparator = hmac.compare_digest) -> str | None:
        """Return the customer for a valid key, otherwise None."""
        parsed = split_api_key(presented_key)
        if parsed is None:
            return None
        key_id, secret = parsed
        record = self._records.get(key_id)
        expected = record.secret_digest if record else self._dummy_digest
        # Compare digests, not secrets: how many bytes of two digests match
        # says nothing about how many characters of the secret were right.
        matches = comparator(digest_secret(secret), expected)
        if record is None or not matches:
            return None
        return record.customer


def recover_secret_by_timing(known_prefix: str, secret_length: int,
                             work_for_guess: Callable[[str], int],
                             is_accepted: Callable[[str], bool]) -> str:
    """The attack: for each position keep the character that took the most work.

    ``work_for_guess`` returns how many characters were examined for a guess
    (the attacker's timing measurement); padding fills the unknown tail. The
    last character cannot be found by timing (right and wrong both examine
    every character), so it is found by simply trying all 16 values.
    """
    recovered = ""
    for _position in range(secret_length - 1):
        padding = "0" * (secret_length - len(recovered) - 1)
        best_character = HEX_ALPHABET[0]
        best_work = -1
        for character in HEX_ALPHABET:
            work = work_for_guess(known_prefix + recovered + character + padding)
            if work > best_work:
                best_character, best_work = character, work
        recovered += best_character
    for character in HEX_ALPHABET:
        if is_accepted(known_prefix + recovered + character):
            return recovered + character
    return recovered + HEX_ALPHABET[0]
