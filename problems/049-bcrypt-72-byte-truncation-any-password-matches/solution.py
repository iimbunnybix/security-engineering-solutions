"""bcrypt reads only the first 72 bytes of a password, so long inputs collide.

The login service hashed "<tenant id>:<email>:<password>" with bcrypt. bcrypt
silently ignores everything after byte 72, so for accounts with a long email
the prefix alone filled the limit and ANY password verified. The fix
pre-hashes the password with HMAC-SHA256 (keyed with a secret pepper) and
base64-encodes the 32-byte result into 44 ASCII bytes: always under 72 bytes
and never a NUL byte. Legacy hashes are upgraded on the next good login,
unless the prefix left too little of the password to trust.

bcrypt is not in the standard library, so ``bcrypt_like_kdf`` models its
input handling on top of PBKDF2 with a deliberately tiny iteration count.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass

# bcrypt's key schedule uses at most 72 bytes of the password.
BCRYPT_MAX_PASSWORD_BYTES = 72
# Tiny so the tests run fast. Real deployments use bcrypt cost 12 or more.
MODEL_KDF_ITERATIONS = 1_000
SALT_BYTES = 16
PEPPER_BYTES = 32
LEGACY_SCHEME = "legacy"
CURRENT_SCHEME = "v2"
# A legacy hash is only trusted for migration if at least this many bytes of
# the password itself fitted inside the 72-byte window.
MIN_LEGACY_PASSWORD_BYTES_COUNTED = 12


def bcrypt_like_kdf(secret: bytes, salt: bytes) -> bytes:
    """Model of how bcrypt treats its input: only what it can 'see' is hashed.

    C implementations take the password as a NUL-terminated string, so input
    stops at the first NUL byte, and then only the first 72 bytes are used.
    """
    visible = secret.split(b"\0", 1)[0]
    truncated = visible[:BCRYPT_MAX_PASSWORD_BYTES]
    return hashlib.pbkdf2_hmac("sha256", truncated, salt, MODEL_KDF_ITERATIONS)


def encode_hash(scheme: str, salt: bytes, digest: bytes) -> str:
    """Store the scheme next to the hash so old and new formats can coexist."""
    return f"{scheme}${salt.hex()}${digest.hex()}"


def decode_hash(stored: str) -> tuple[str, bytes, bytes]:
    """Split a stored hash into (scheme, salt, digest)."""
    scheme, salt_hex, digest_hex = stored.split("$")
    return scheme, bytes.fromhex(salt_hex), bytes.fromhex(digest_hex)


def make_pepper() -> bytes:
    """A random secret kept outside the database (e.g. in a secrets manager)."""
    return os.urandom(PEPPER_BYTES)


# ---- original, vulnerable scheme ------------------------------------------

def legacy_prefix(tenant_id: str, email: str) -> bytes:
    """The bytes the original code put in front of every password."""
    return f"{tenant_id}:{email}:".encode()


def naive_hash_password(tenant_id: str, email: str, password: str) -> str:
    """Original code: bcrypt(tenant:email:password). The prefix eats the 72 bytes."""
    salt = os.urandom(SALT_BYTES)
    secret = legacy_prefix(tenant_id, email) + password.encode()
    return encode_hash(LEGACY_SCHEME, salt, bcrypt_like_kdf(secret, salt))


def naive_verify_password(tenant_id: str, email: str, password: str, stored: str) -> bool:
    """Original check. Bytes beyond 72 never reach the KDF, so they are never checked."""
    _, salt, expected = decode_hash(stored)
    secret = legacy_prefix(tenant_id, email) + password.encode()
    return hmac.compare_digest(bcrypt_like_kdf(secret, salt), expected)


# ---- fixed scheme ---------------------------------------------------------

def prehash_password(password: str, pepper: bytes) -> bytes:
    """HMAC-SHA256 the full password, then base64 it.

    The HMAC covers every byte of the password, however long. The raw digest
    may contain NUL bytes, which would cut the input short in bcrypt, so it
    is base64-encoded: 44 printable ASCII bytes, well under the 72-byte limit.
    """
    digest = hmac.new(pepper, password.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest)


def hash_password(password: str, pepper: bytes) -> str:
    """New scheme: bcrypt(base64(HMAC-SHA256(pepper, password))) with a random salt."""
    salt = os.urandom(SALT_BYTES)
    digest = bcrypt_like_kdf(prehash_password(password, pepper), salt)
    return encode_hash(CURRENT_SCHEME, salt, digest)


def verify_password(password: str, stored: str, pepper: bytes) -> bool:
    """Check a password against a hash made by ``hash_password``."""
    scheme, salt, expected = decode_hash(stored)
    if scheme != CURRENT_SCHEME:
        return False
    actual = bcrypt_like_kdf(prehash_password(password, pepper), salt)
    return hmac.compare_digest(actual, expected)


# ---- migration ------------------------------------------------------------

@dataclass
class Account:
    tenant_id: str
    email: str
    password_hash: str
    reset_required: bool = False


def legacy_password_bytes_counted(account: Account) -> int:
    """How many bytes of the password fitted inside bcrypt's 72-byte window."""
    room = BCRYPT_MAX_PASSWORD_BYTES - len(legacy_prefix(account.tenant_id, account.email))
    return max(room, 0)


def login(account: Account, password: str, pepper: bytes) -> bool:
    """Verify a password, upgrading legacy hashes to the new scheme on success.

    A legacy hash whose prefix left fewer than MIN_LEGACY_PASSWORD_BYTES_COUNTED
    bytes for the password proves almost nothing, so it is never accepted:
    the account is flagged for a password reset instead.
    """
    scheme, _, _ = decode_hash(account.password_hash)
    if scheme == CURRENT_SCHEME:
        return verify_password(password, account.password_hash, pepper)
    if legacy_password_bytes_counted(account) < MIN_LEGACY_PASSWORD_BYTES_COUNTED:
        account.reset_required = True
        return False
    if not naive_verify_password(account.tenant_id, account.email, password,
                                 account.password_hash):
        return False
    # We now hold the plaintext, so re-hash it with the safe scheme.
    account.password_hash = hash_password(password, pepper)
    return True
