"""Store API keys as peppered HMACs plus a short public prefix, never in plain text.

The original key table kept every customer's full API key in a ``key``
column. A read-only analytics replica (and its nightly backups) copied that
column, so whoever obtained a backup could call the API as every customer.

The fix keeps only (a) a short random prefix that is not secret, used to find
the row and to show the key in the dashboard, and (b) HMAC-SHA256 of the full
key under a server-side pepper that lives outside the database. A leaked table
then contains nothing that authenticates, and without the pepper an attacker
cannot even test guesses offline. Keys are compared with
``hmac.compare_digest`` and the full key is returned exactly once, at creation.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Callable

KEY_TAG = "dk"              # fixed marker so scanners and humans recognise the key type
PREFIX_HEX_CHARS = 12       # 48 random bits: unique lookup handle, not a secret
SECRET_HEX_CHARS = 64       # 256 random bits: the part that actually authenticates
PEPPER_BYTES = 32
MAX_PREFIX_ATTEMPTS = 5     # a 48-bit prefix colliding even twice in a row is a bug
MASK = "…"

# Returns ``n`` random hex characters; injectable so tests can force collisions.
HexSource = Callable[[int], str]
Comparator = Callable[[bytes, bytes], bool]


def random_hex(n_chars: int) -> str:
    """Cryptographically random hex string of ``n_chars`` characters."""
    return secrets.token_hex((n_chars + 1) // 2)[:n_chars]


def build_key(prefix: str, secret: str) -> str:
    """Assemble ``dk_<prefix>_<secret>``."""
    return f"{KEY_TAG}_{prefix}_{secret}"


def parse_prefix(presented_key: str) -> str | None:
    """Return the lookup prefix of a well-formed key, otherwise None."""
    parts = presented_key.split("_")
    if len(parts) != 3 or parts[0] != KEY_TAG:
        return None
    prefix, secret = parts[1], parts[2]
    if len(prefix) != PREFIX_HEX_CHARS or len(secret) != SECRET_HEX_CHARS:
        return None
    return prefix


# ---------------------------------------------------------------- original
class NaiveKeyTable:
    """ORIGINAL: full key -> customer, exactly what the replica copied."""

    def __init__(self) -> None:
        self.rows: dict[str, str] = {}

    def create_key(self, customer: str) -> str:
        """Generate a key and store it in plain text."""
        api_key = build_key(random_hex(PREFIX_HEX_CHARS), random_hex(SECRET_HEX_CHARS))
        self.rows[api_key] = customer
        return api_key

    def authenticate(self, presented_key: str) -> str | None:
        """Look the presented key up directly."""
        return self.rows.get(presented_key)

    def dump(self) -> list[dict[str, str]]:
        """What a backup or replica of the table contains."""
        return [{"key": key, "customer": customer} for key, customer in self.rows.items()]


# --------------------------------------------------------------------- fix
@dataclass(frozen=True)
class KeyRow:
    """One database row. Nothing here is enough to authenticate."""
    prefix: str
    customer: str
    key_hmac: bytes


@dataclass(frozen=True)
class IssuedKey:
    """Returned once by ``create_key``; ``full_key`` is never stored."""
    full_key: str
    prefix: str


def keyed_hash(pepper: bytes, full_key: str) -> bytes:
    """HMAC-SHA256 of the whole key under the server-side pepper."""
    return hmac.new(pepper, full_key.encode(), hashlib.sha256).digest()


class HashedKeyStore:
    """FIX: stores prefix + HMAC; the pepper is held by the app, not the DB."""

    def __init__(self, pepper: bytes, hex_source: HexSource = random_hex) -> None:
        if len(pepper) < PEPPER_BYTES:
            raise ValueError("pepper must be at least 32 random bytes")
        self._pepper = pepper
        self._hex_source = hex_source
        self._rows: dict[str, KeyRow] = {}
        # Unknown prefixes are compared against this so they do the same work.
        self._dummy_hmac = keyed_hash(pepper, "unknown-prefix")

    def _new_prefix(self) -> str:
        """Pick a prefix not already in use; refuse to overwrite another key."""
        for _attempt in range(MAX_PREFIX_ATTEMPTS):
            prefix = self._hex_source(PREFIX_HEX_CHARS)
            if prefix not in self._rows:
                return prefix
        raise RuntimeError("could not find an unused key prefix")

    def create_key(self, customer: str) -> IssuedKey:
        """Create a key, store only its HMAC, and hand the full key back once."""
        prefix = self._new_prefix()
        full_key = build_key(prefix, self._hex_source(SECRET_HEX_CHARS))
        self._rows[prefix] = KeyRow(prefix, customer, keyed_hash(self._pepper, full_key))
        return IssuedKey(full_key, prefix)

    def import_plaintext_key(self, full_key: str, customer: str) -> None:
        """Migration: hash an existing plain-text key so customers keep it."""
        prefix = parse_prefix(full_key)
        if prefix is None:
            raise ValueError("malformed API key")
        if prefix in self._rows:
            raise ValueError("prefix already in use")
        self._rows[prefix] = KeyRow(prefix, customer, keyed_hash(self._pepper, full_key))

    def authenticate(self, presented_key: str,
                     comparator: Comparator = hmac.compare_digest) -> str | None:
        """Return the customer for a valid key, otherwise None."""
        prefix = parse_prefix(presented_key)
        if prefix is None:
            return None
        row = self._rows.get(prefix)
        expected = row.key_hmac if row is not None else self._dummy_hmac
        # Always run exactly one constant-time comparison, found or not.
        matches = comparator(keyed_hash(self._pepper, presented_key), expected)
        if row is None or not matches:
            return None
        return row.customer

    def revoke(self, prefix: str) -> bool:
        """Delete a key by its public prefix (what the dashboard shows)."""
        return self._rows.pop(prefix, None) is not None

    def display_keys(self, customer: str) -> list[str]:
        """Dashboard view: tag and prefix only, the secret part masked."""
        shown = []
        for row in self._rows.values():
            if row.customer == customer:
                shown.append(f"{KEY_TAG}_{row.prefix}_{MASK}")
        return shown

    def dump(self) -> list[KeyRow]:
        """What a backup or replica of the table contains."""
        return list(self._rows.values())


def migrate_plaintext_table(old_table: NaiveKeyTable, new_store: HashedKeyStore) -> int:
    """Move every plain-text row into the hashed store and wipe the old rows."""
    migrated = 0
    for full_key, customer in list(old_table.rows.items()):
        new_store.import_plaintext_key(full_key, customer)
        # Delete as we go: the plain-text copy is the liability being removed.
        del old_table.rows[full_key]
        migrated += 1
    return migrated
