"""Versioned password hashing with wrap-then-upgrade migration from unsalted SHA-1."""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets

ALGO = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000          # OWASP 2023 guidance for PBKDF2-HMAC-SHA256


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _pbkdf2(secret: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, iterations)


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    return f"{ALGO}${iterations}${_b64(salt)}${_b64(_pbkdf2(password, salt, iterations))}"


def wrap_legacy_sha1(sha1_hex: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Batch migration step: strengthen an existing sha1 hash without the password."""
    salt = secrets.token_bytes(16)
    return f"wrapped${iterations}${_b64(salt)}${_b64(_pbkdf2(sha1_hex.lower(), salt, iterations))}"


def parse_versioned_hash(stored: str) -> tuple[str, int, bytes, bytes] | None:
    """Split "kind$iterations$salt$hash" into parts, or None if it is malformed.

    A corrupted row (bad migration batch, manual edit) must make login fail
    closed, not raise and turn into an HTTP 500.
    """
    parts = stored.split("$")
    if len(parts) != 4 or parts[0] not in (ALGO, "wrapped"):
        return None
    kind, iters_text, salt_b64, hash_b64 = parts
    try:
        iterations = int(iters_text)
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
    except (ValueError, binascii.Error):
        return None
    if iterations <= 0:
        return None
    return kind, iterations, salt, expected


def verify(password: str, stored: str) -> bool:
    parsed = parse_versioned_hash(stored)
    if parsed is not None:
        kind, iterations, salt, expected = parsed
        secret = password if kind == ALGO else hashlib.sha1(password.encode()).hexdigest()
        return hmac.compare_digest(_pbkdf2(secret, salt, iterations), expected)
    if "$" in stored:                                       # versioned but malformed
        return False
    if len(stored) == 40:                                   # raw legacy sha1, not yet wrapped
        return hmac.compare_digest(hashlib.sha1(password.encode()).hexdigest(), stored.lower())
    return False


def needs_rehash(stored: str, iterations: int = DEFAULT_ITERATIONS) -> bool:
    parsed = parse_versioned_hash(stored)
    return not (parsed is not None and parsed[0] == ALGO and parsed[1] >= iterations)


class UserStore:
    def __init__(self, iterations: int = DEFAULT_ITERATIONS):
        self.iterations = iterations
        self.hashes: dict[str, str] = {}
        # Built once so the unknown-user path runs PBKDF2 exactly once per login,
        # the same as a wrong password for a real user (building it per login
        # would double the work and leak "user does not exist" via timing).
        self._dummy_hash = hash_password("dummy", iterations)

    def wrap_all_legacy(self) -> int:
        n = 0
        for user, h in self.hashes.items():
            if "$" not in h and len(h) == 40:
                self.hashes[user] = wrap_legacy_sha1(h, self.iterations)
                n += 1
        return n

    def login(self, user: str, password: str) -> bool:
        stored = self.hashes.get(user)
        if stored is None:
            # do equivalent work so "unknown user" is not faster than "wrong password"
            verify(password, self._dummy_hash)
            return False
        if not verify(password, stored):
            return False
        if needs_rehash(stored, self.iterations):
            self.hashes[user] = hash_password(password, self.iterations)
        return True
