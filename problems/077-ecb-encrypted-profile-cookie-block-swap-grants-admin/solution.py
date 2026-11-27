"""An ECB-encrypted profile cookie let users cut and paste their way to admin.

The legacy app stored ``email=...&role=user&uid=...`` in a cookie encrypted
with a block cipher in ECB mode and no MAC. ECB encrypts every 16-byte block
on its own, so the same plaintext block always gives the same ciphertext
block, and blocks from different cookies can be glued together. By
registering two crafted emails, an attacker gets a block that decrypts to
"admin" plus padding and pastes it where "user" was.

The fix stops trusting an encrypted client blob. The cookie becomes a signed
token: JSON payload plus an HMAC-SHA256 tag checked with
``hmac.compare_digest`` before anything is parsed. Any spliced, edited or
foreign token is rejected, and the email is JSON-encoded so it cannot inject
fields.

TEACHING TOY ONLY: Python's standard library has no AES, so ``toy_encrypt_block``
is a 4-round Feistel network built from HMAC-SHA256. It exists only to show
ECB's structure. Never use it to protect anything.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from typing import Callable

BLOCK_SIZE = 16
HALF_BLOCK = BLOCK_SIZE // 2
FEISTEL_ROUNDS = 4
SIGNED_TOKEN_SEPARATOR = "."


class InvalidToken(ValueError):
    """The cookie was not issued by this server, or was changed (HTTP 401)."""


# ------------------------------------------------------- toy block cipher
def _round_function(key: bytes, round_number: int, half: bytes) -> bytes:
    """Keyed pseudo-random function for one Feistel round (8 bytes out)."""
    message = bytes([round_number]) + half
    return hmac.new(key, message, hashlib.sha256).digest()[:HALF_BLOCK]


def _xor(left: bytes, right: bytes) -> bytes:
    """XOR two byte strings of the same length."""
    result = bytearray()
    for a, b in zip(left, right):
        result.append(a ^ b)
    return bytes(result)


def toy_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt exactly one 16-byte block with the toy Feistel cipher."""
    left, right = block[:HALF_BLOCK], block[HALF_BLOCK:]
    for round_number in range(FEISTEL_ROUNDS):
        left, right = right, _xor(left, _round_function(key, round_number, right))
    return left + right


def toy_decrypt_block(key: bytes, block: bytes) -> bytes:
    """Undo toy_encrypt_block by running the rounds backwards."""
    left, right = block[:HALF_BLOCK], block[HALF_BLOCK:]
    for round_number in reversed(range(FEISTEL_ROUNDS)):
        left, right = _xor(right, _round_function(key, round_number, left)), left
    return left + right


def pkcs7_pad(data: bytes) -> bytes:
    """Pad to a whole number of blocks; each pad byte holds the pad length."""
    pad_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_length]) * pad_length


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding, refusing malformed padding."""
    pad_length = data[-1] if data else 0
    if pad_length < 1 or pad_length > BLOCK_SIZE:
        raise ValueError("bad padding")
    if data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("bad padding")
    return data[:-pad_length]


def split_blocks(data: bytes) -> list[bytes]:
    """Cut data into 16-byte blocks."""
    blocks = []
    for start in range(0, len(data), BLOCK_SIZE):
        blocks.append(data[start:start + BLOCK_SIZE])
    return blocks


def ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """ECB mode: every block is encrypted alone, with nothing linking them."""
    ciphertext = b""
    for block in split_blocks(pkcs7_pad(plaintext)):
        ciphertext += toy_encrypt_block(key, block)
    return ciphertext


def ecb_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt block by block; any sequence of valid blocks decrypts fine."""
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise ValueError("ciphertext is not whole blocks")
    plaintext = b""
    for block in split_blocks(ciphertext):
        plaintext += toy_decrypt_block(key, block)
    return pkcs7_unpad(plaintext)


# ---------------------------------------------------------------- original
def original_profile_for(email: str, uid: int) -> str:
    """Build the legacy profile string. Only '&' and '=' are stripped."""
    clean_email = email.replace("&", "").replace("=", "")
    return f"email={clean_email}&role=user&uid={uid}"


def original_parse_profile(text: str) -> dict[str, str]:
    """Parse 'k=v&k=v' into a dict, the way the legacy app did."""
    fields = {}
    for pair in text.split("&"):
        name, _, value = pair.partition("=")
        fields[name] = value
    return fields


def original_issue_cookie(key: bytes, email: str, uid: int) -> bytes:
    """Legacy login: ECB-encrypt the profile and hand it to the browser."""
    return ecb_encrypt(key, original_profile_for(email, uid).encode())


def original_read_cookie(key: bytes, cookie: bytes) -> dict[str, str]:
    """Legacy request handling: decrypt and trust whatever comes out."""
    return original_parse_profile(ecb_decrypt(key, cookie).decode("latin-1"))


# ------------------------------------------------------------------ attack
def forge_admin_cookie_by_block_swap(register: Callable[[str], bytes]) -> bytes:
    """Build an admin cookie using only the app's own register endpoint.

    register(email) returns the cookie the app issues for that email.
    The attacker never sees the key.
    """
    prefix_length = len("email=")
    # Step 1: fill block 0, then put "admin"+padding exactly in block 1.
    filler = "A" * (BLOCK_SIZE - prefix_length)
    admin_block_text = pkcs7_pad(b"admin").decode("latin-1")
    admin_block = split_blocks(register(filler + admin_block_text))[1]
    # Step 2: choose an email length so "&role=" ends on a block boundary;
    # then "user&uid=..." starts a fresh block that we can drop.
    text_before_role_value = len("email=") + len("&role=")
    email_length = (-text_before_role_value) % BLOCK_SIZE + BLOCK_SIZE
    victim_email = "e" * (email_length - len("@evil.test")) + "@evil.test"
    blocks = split_blocks(register(victim_email))
    blocks_up_to_role = (text_before_role_value + email_length) // BLOCK_SIZE
    # Step 3: keep "email=...&role=" and paste the admin block after it.
    return b"".join(blocks[:blocks_up_to_role]) + admin_block


# ---------------------------------------------------------------- the fix
def _b64encode(data: bytes) -> str:
    """URL-safe base64 without '=' padding, safe inside a cookie."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    """Reverse _b64encode, restoring the '=' padding it removed."""
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(signing_key: bytes, payload_text: str) -> str:
    """HMAC-SHA256 tag over the encoded payload, base64 encoded."""
    tag = hmac.new(signing_key, payload_text.encode("ascii"), hashlib.sha256)
    return _b64encode(tag.digest())


def issue_signed_token(signing_key: bytes, email: str, uid: int) -> str:
    """Issue 'payload.tag'. The server sets role; JSON keeps email a value."""
    profile = {"email": email, "role": "user", "uid": uid}
    payload_text = _b64encode(json.dumps(profile, sort_keys=True).encode())
    return payload_text + SIGNED_TOKEN_SEPARATOR + _sign(signing_key, payload_text)


def read_signed_token(signing_key: bytes, token: str) -> dict:
    """Return the profile only if the tag matches; otherwise InvalidToken."""
    payload_text, separator, tag_text = token.partition(SIGNED_TOKEN_SEPARATOR)
    if not separator or not payload_text:
        raise InvalidToken("malformed token")
    expected_tag = _sign(signing_key, payload_text)
    # WHY compare_digest: a normal == leaks via timing how many bytes matched.
    if not hmac.compare_digest(expected_tag.encode(), tag_text.encode()):
        raise InvalidToken("bad signature")
    # Only now is the payload trusted enough to decode and parse.
    try:
        return json.loads(_b64decode(payload_text))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InvalidToken("unreadable payload") from error
