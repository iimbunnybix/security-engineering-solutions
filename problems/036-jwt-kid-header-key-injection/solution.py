"""Choose the JWT verification key from a server-side keyring, never from a path in the token.

The original verifier read the ``kid`` (key id) header of the incoming token
and loaded ``keys/<kid>`` from disk as the HMAC key. If the file did not
exist it fell back to an empty "default" key so a half-finished key rotation
would not cause an outage. An attacker could set ``kid`` to ``../static/app.css``
(a public file whose bytes anyone can download) or to any unknown id, sign
the token with that predictable key, and be accepted as an admin.

The fix: keys live in an in-memory ``Keyring`` loaded at startup. ``kid`` is
only used as a dictionary key; it must be a short id from the allowlist,
unknown ids are rejected with no fallback, and each key pins the one
algorithm it may be used with.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Callable

# Supported HMAC algorithms. Each key is pinned to exactly one of these.
HASH_FOR_ALG: dict[str, Callable[..., Any]] = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}
MIN_KEY_BYTES = 32                     # RFC 7518 section 3.2: HS256 key >= 256 bits
KID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}")
MAX_TOKEN_LENGTH = 8192


class InvalidToken(Exception):
    """Any verification failure. Clients only ever see a 401."""


# --- encoding helpers ---------------------------------------------------
def b64url_encode(raw: bytes) -> str:
    """Base64url without padding, as JWTs use."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Inverse of ``b64url_encode``; raises InvalidToken on bad input."""
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError) as exc:
        raise InvalidToken("bad base64") from exc


def sign(claims: dict[str, Any], key: bytes, kid: str, alg: str = "HS256") -> str:
    """Build a signed compact JWT. Used by the issuer and, in tests, by the attacker."""
    header = {"alg": alg, "typ": "JWT", "kid": kid}
    head = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    body = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signature = hmac.new(key, f"{head}.{body}".encode(), HASH_FOR_ALG[alg]).digest()
    return f"{head}.{body}.{b64url_encode(signature)}"


def split_token(token: str) -> tuple[dict[str, Any], str, str, str]:
    """Return (header, header segment, payload segment, signature segment)."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH:
        raise InvalidToken("token missing or too long")
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidToken("not a compact JWS")
    try:
        header = json.loads(b64url_decode(parts[0]))
    except ValueError as exc:
        raise InvalidToken("bad header") from exc
    if not isinstance(header, dict):
        raise InvalidToken("header must be an object")
    return header, parts[0], parts[1], parts[2]


def check_signature(head: str, body: str, sig: str, key: bytes, alg: str) -> dict[str, Any]:
    """Constant-time HMAC check, then parse the payload (only after it is authentic)."""
    expected = hmac.new(key, f"{head}.{body}".encode(), HASH_FOR_ALG[alg]).digest()
    if not hmac.compare_digest(expected, b64url_decode(sig)):
        raise InvalidToken("bad signature")
    try:
        claims = json.loads(b64url_decode(body))
    except ValueError as exc:
        raise InvalidToken("bad payload") from exc
    if not isinstance(claims, dict):
        raise InvalidToken("payload must be an object")
    return claims


# --- original version ---------------------------------------------------
DEFAULT_KEY = b""   # "temporary" fallback added during a key rotation


def naive_verify(token: str, keys_dir: str) -> dict[str, Any]:
    """The bug: ``kid`` becomes a file path, and a missing file means "use the default key"."""
    header, head, body, sig = split_token(token)
    if header.get("alg") not in HASH_FOR_ALG:
        raise InvalidToken("algorithm not allowed")
    key_path = os.path.join(keys_dir, str(header.get("kid", "")))
    try:
        with open(key_path, "rb") as fh:
            key = fh.read()
    except OSError:
        key = DEFAULT_KEY
    return check_signature(head, body, sig, key, header["alg"])


# --- fixed version ------------------------------------------------------
@dataclass(frozen=True)
class KeyEntry:
    """One signing key and the single algorithm it is allowed to verify."""

    kid: str
    alg: str
    secret: bytes


class Keyring:
    """Allowlist of verification keys, loaded once at startup (e.g. from a secret manager)."""

    def __init__(self, entries: list[KeyEntry]):
        """Validate every key up front so a bad config fails at boot, not per request."""
        self._entries: dict[str, KeyEntry] = {}
        for entry in entries:
            if not KID_PATTERN.fullmatch(entry.kid):
                raise ValueError(f"key id {entry.kid!r} has invalid characters")
            if entry.alg not in HASH_FOR_ALG:
                raise ValueError(f"key {entry.kid!r}: unsupported algorithm {entry.alg!r}")
            if len(entry.secret) < MIN_KEY_BYTES:
                raise ValueError(f"key {entry.kid!r} is shorter than {MIN_KEY_BYTES} bytes")
            if entry.kid in self._entries:
                raise ValueError(f"duplicate key id {entry.kid!r}")
            self._entries[entry.kid] = entry
        if not self._entries:
            raise ValueError("keyring is empty")

    def lookup(self, kid: Any) -> KeyEntry:
        """Return the entry for ``kid``; anything not on the allowlist is rejected."""
        # WHY: kid is attacker-controlled JSON. Only a plain short id string is
        # accepted; it is used as a dict key and never touches the filesystem.
        if not isinstance(kid, str) or not KID_PATTERN.fullmatch(kid):
            raise InvalidToken("bad key id")
        entry = self._entries.get(kid)
        if entry is None:
            raise InvalidToken("unknown key id")   # no default key, no fallback
        return entry


def check_expiry(claims: dict[str, Any], now: float) -> None:
    """Require a numeric ``exp`` in the future."""
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise InvalidToken("exp missing")
    if now >= exp:
        raise InvalidToken("token expired")


def verify(token: str, keyring: Keyring, clock: Callable[[], float] = time.time) -> dict[str, Any]:
    """Verify a token using only keys from ``keyring``; return its claims."""
    header, head, body, sig = split_token(token)
    entry = keyring.lookup(header.get("kid"))
    # WHY: the key, not the token, decides the algorithm. A token that names a
    # different algorithm for this key is rejected rather than "adapted to".
    if header.get("alg") != entry.alg:
        raise InvalidToken("algorithm does not match key")
    claims = check_signature(head, body, sig, entry.secret, entry.alg)
    check_expiry(claims, clock())
    return claims
