"""JWT verification that checks who the token was issued *for* (``aud``).

Several internal services trust one token issuer and one HMAC signing key.
The payments admin API verified the signature and the expiry of incoming
JWTs but never looked at the ``aud`` (audience) claim. A low-privilege token
minted for the read-only reporting service is signed by the same key, so it
passed verification and was accepted by the payments admin API.

The fix: after the signature and expiry checks, require ``iss`` to equal the
trusted issuer and require ``aud`` (a string or a list of strings) to contain
this service's own identifier. Missing or malformed claims are rejected.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

TRUSTED_ISSUER = "https://auth.internal.example"
REPORTING_SERVICE = "reporting-api"
PAYMENTS_ADMIN_SERVICE = "payments-admin-api"
EXPECTED_HEADER = {"alg": "HS256", "typ": "JWT"}
# Allow a little clock difference between servers when checking ``exp``.
CLOCK_SKEW_S = 30


class InvalidToken(Exception):
    """The token is malformed, forged, expired, or not meant for us."""


def b64url_encode(raw: bytes) -> str:
    """Base64url without padding, as JWTs use."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Inverse of ``b64url_encode``; raises InvalidToken on bad input."""
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as error:
        raise InvalidToken("bad base64") from error


def sign(key: bytes, claims: dict) -> str:
    """Issue an HS256 JWT (what the shared token issuer does)."""
    header = b64url_encode(json.dumps(EXPECTED_HEADER).encode())
    payload = b64url_encode(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url_encode(signature)}"


def verify_signature_and_expiry(key: bytes, token: str, now: int) -> dict:
    """Check structure, header, HMAC and ``exp``; return the claims.

    This is everything the original service checked. It proves the token
    came from our issuer and is fresh, but NOT that it was meant for us.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise InvalidToken("token must have three parts")
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64))
        claims = json.loads(b64url_decode(payload_b64))
    except (ValueError, UnicodeDecodeError) as error:
        raise InvalidToken("bad JSON") from error
    if header != EXPECTED_HEADER:
        raise InvalidToken("unexpected header")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(b64url_decode(signature_b64), expected):
        raise InvalidToken("bad signature")
    if not isinstance(claims, dict):
        raise InvalidToken("claims must be a JSON object")
    expires_at = claims.get("exp")
    # bool is a subclass of int in Python, so exclude it explicitly.
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise InvalidToken("missing or non-integer exp")
    if now >= expires_at + CLOCK_SKEW_S:
        raise InvalidToken("expired")
    return claims


# --- original version ---------------------------------------------------
def naive_verify(key: bytes, token: str, now: int) -> dict:
    """The bug: signature and expiry only; ``aud`` and ``iss`` are ignored."""
    return verify_signature_and_expiry(key, token, now)


# --- fixed version ------------------------------------------------------
def audiences_in(claims: dict) -> list[str]:
    """Return ``aud`` as a list. RFC 7519 allows a string or a list of strings."""
    audience = claims.get("aud")
    if isinstance(audience, str):
        return [audience]
    if isinstance(audience, list) and audience:
        for entry in audience:
            if not isinstance(entry, str):
                raise InvalidToken("aud list must contain only strings")
        return audience
    raise InvalidToken("missing or malformed aud")


def verify_for_service(key: bytes, token: str, now: int, service_id: str,
                       issuer: str = TRUSTED_ISSUER) -> dict:
    """Verify a token and check it was issued by ``issuer`` for ``service_id``."""
    claims = verify_signature_and_expiry(key, token, now)
    # Exact string match: no prefix, substring or case-insensitive tricks.
    if claims.get("iss") != issuer:
        raise InvalidToken("wrong or missing iss")
    if service_id not in audiences_in(claims):
        raise InvalidToken(f"token is not intended for {service_id}")
    return claims
