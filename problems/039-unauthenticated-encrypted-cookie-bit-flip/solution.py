"""Stop bit-flipping attacks on an encrypted (but not authenticated) cookie.

The shop stored ``uid=1042;role=user`` in a cookie encrypted with a stream
cipher (CTR mode). Encryption hides the text but does not stop changes:
flipping a bit in the ciphertext flips the same bit in the decrypted text,
so a user who can guess the plaintext can turn ``role=user`` into
``role=root`` without knowing the key.

The fix is authenticated encryption (encrypt-then-MAC): a fresh random nonce
per cookie, a separate MAC key, an HMAC-SHA256 tag over nonce and ciphertext,
and a constant-time tag check BEFORE anything is decrypted or parsed.

The keystream here is HMAC-SHA256 used as a pseudo-random function in
counter mode, so the example runs with the standard library only. In
production use AES-GCM or ChaCha20-Poly1305 from a vetted library.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

NONCE_BYTES = 16
TAG_BYTES = 32
BLOCK_BYTES = 32  # one HMAC-SHA256 output per keystream block
COUNTER_BYTES = 8

# The broken version used one fixed nonce for every cookie.
FIXED_NONCE = bytes(NONCE_BYTES)


class InvalidCookie(ValueError):
    """The cookie was modified, truncated or made with another key."""


def keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    """Return ``length`` pseudo-random bytes derived from key and nonce."""
    blocks = []
    counter = 0
    while len(blocks) * BLOCK_BYTES < length:
        counter_bytes = counter.to_bytes(COUNTER_BYTES, "big")
        blocks.append(hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest())
        counter += 1
    return b"".join(blocks)[:length]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    result = bytearray()
    for index in range(len(left)):
        result.append(left[index] ^ right[index])
    return bytes(result)


def parse_session(plaintext: bytes) -> dict[str, str]:
    """Parse ``uid=1;role=user`` into a dict."""
    session = {}
    for part in plaintext.decode("utf-8").split(";"):
        name, _, value = part.partition("=")
        session[name] = value
    return session


def encode_session(session: dict[str, str]) -> bytes:
    """Serialise a session dict as ``key=value;key=value``."""
    parts = []
    for name, value in session.items():
        parts.append(f"{name}={value}")
    return ";".join(parts).encode("utf-8")


# ---------------------------------------------------------------- original
def naive_seal(key: bytes, session: dict[str, str]) -> bytes:
    """Original code: encryption only, fixed nonce, no integrity check."""
    plaintext = encode_session(session)
    return xor_bytes(plaintext, keystream(key, FIXED_NONCE, len(plaintext)))


def naive_open(key: bytes, cookie: bytes) -> dict[str, str]:
    """Original code: decrypts whatever it is given and trusts the result."""
    plaintext = xor_bytes(cookie, keystream(key, FIXED_NONCE, len(cookie)))
    return parse_session(plaintext)


def flip_bytes(cookie: bytes, offset: int, known_text: bytes, wanted_text: bytes) -> bytes:
    """What the attacker does: no key, just XOR (known ^ wanted) into the bytes.

    ``ciphertext = plaintext ^ keystream``, so XORing the difference between
    two plaintexts into the ciphertext at ``offset`` changes the decrypted
    text there to ``wanted_text``. The cookie format is public, so the
    attacker knows the plaintext of his own cookie.
    """
    difference = xor_bytes(known_text, wanted_text)
    edited = bytearray(cookie)
    for index in range(len(difference)):
        edited[offset + index] ^= difference[index]
    return bytes(edited)


# --------------------------------------------------------------------- fix
def seal(encryption_key: bytes, mac_key: bytes, session: dict[str, str]) -> bytes:
    """Encrypt-then-MAC: ``nonce || ciphertext || tag``."""
    plaintext = encode_session(session)
    # A fresh nonce per cookie: reusing one lets an attacker XOR two cookies
    # together and cancel the keystream.
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = xor_bytes(plaintext, keystream(encryption_key, nonce, len(plaintext)))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + tag


def open_sealed(encryption_key: bytes, mac_key: bytes, cookie: bytes) -> dict[str, str]:
    """Verify the tag first, then decrypt. Any change raises ``InvalidCookie``."""
    if len(cookie) < NONCE_BYTES + TAG_BYTES:
        raise InvalidCookie("cookie too short")
    nonce = cookie[:NONCE_BYTES]
    ciphertext = cookie[NONCE_BYTES:-TAG_BYTES]
    tag = cookie[-TAG_BYTES:]
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    # Constant-time compare, and no decryption before the check, so the
    # attacker learns nothing from how a modified cookie fails.
    if not hmac.compare_digest(tag, expected):
        raise InvalidCookie("cookie failed integrity check")
    plaintext = xor_bytes(ciphertext, keystream(encryption_key, nonce, len(ciphertext)))
    return parse_session(plaintext)
