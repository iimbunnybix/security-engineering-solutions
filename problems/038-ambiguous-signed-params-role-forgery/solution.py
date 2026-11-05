"""Sign invite links so one set of parameters can never pass as another.

Anyone can request a self-service invite, which the server signs with role
``viewer``. The original signer joined every query parameter as
``key=value&key=value`` (sorted by key) and signed that string. Values were
not escaped, so an email address containing ``&role=admin&z=`` produces the
same signed string as a *different* parameter set with ``role=admin``: the
attacker reuses the signature and joins as an admin.

The fix signs an unambiguous encoding (each key and value length-prefixed)
of a fixed set of fields, rejects links with extra or missing fields, and
validates the email before signing.
"""
from __future__ import annotations

import hashlib
import hmac
import re

SIGNED_FIELDS = ("email", "role")
SELF_SERVICE_ROLE = "viewer"
# A deliberately simple email shape: no '&', '=', spaces or control characters.
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


class InvalidInvite(ValueError):
    """Raised when an invite link is malformed or its signature does not match."""


def _hmac_hex(key: bytes, message: str) -> str:
    """HMAC-SHA256 of ``message`` as hex."""
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------
# Original implementation (kept to reproduce the forgery)
# --------------------------------------------------------------------------
def naive_canonical(params: dict[str, str]) -> str:
    """Join all params as key=value&... without escaping (ambiguous)."""
    parts = []
    for key in sorted(params):
        parts.append(f"{key}={params[key]}")
    return "&".join(parts)


def naive_issue_invite(key: bytes, email: str) -> dict[str, str]:
    """Self-service invite: always role=viewer, email taken as typed."""
    params = {"email": email, "role": SELF_SERVICE_ROLE}
    params["sig"] = _hmac_hex(key, naive_canonical(params))
    return params


def naive_accept_invite(key: bytes, params: dict[str, str]) -> tuple[str, str]:
    """Return (email, role) if the signature over all other params matches."""
    unsigned = dict(params)
    signature = unsigned.pop("sig", "")
    if not hmac.compare_digest(signature, _hmac_hex(key, naive_canonical(unsigned))):
        raise InvalidInvite("bad signature")
    return unsigned["email"], unsigned["role"]


# --------------------------------------------------------------------------
# Fixed implementation
# --------------------------------------------------------------------------
def canonical(params: dict[str, str]) -> str:
    """Encode exactly SIGNED_FIELDS as 'len:key' + 'len:value' pairs.

    Length prefixes make the encoding injective: no choice of values can
    shift text from one field into another.
    """
    parts = []
    for field in SIGNED_FIELDS:
        value = params[field]
        parts.append(f"{len(field)}:{field}{len(value)}:{value}")
    return "".join(parts)


def issue_invite(key: bytes, email: str) -> dict[str, str]:
    """Self-service invite for a validated email, always role=viewer."""
    if not EMAIL_PATTERN.fullmatch(email):
        raise InvalidInvite("invalid email address")
    params = {"email": email, "role": SELF_SERVICE_ROLE}
    params["sig"] = _hmac_hex(key, canonical(params))
    return params


def accept_invite(key: bytes, params: dict[str, str]) -> tuple[str, str]:
    """Return (email, role) for a genuine invite, else raise InvalidInvite."""
    expected_keys = set(SIGNED_FIELDS) | {"sig"}
    if set(params) != expected_keys:
        # Unknown extra params are a sign of tampering; we never ignore them.
        raise InvalidInvite("unexpected or missing parameters")
    expected = _hmac_hex(key, canonical(params))
    if not hmac.compare_digest(params["sig"], expected):
        raise InvalidInvite("bad signature")
    return params["email"], params["role"]


def forge_admin_invite(issued: dict[str, str]) -> dict[str, str]:
    """Attacker: rearrange a self-service invite into an admin invite.

    Works when the requested email was 'eve@...&role=admin&z='. The leftover
    '&role=viewer' is parked in an extra parameter ``z`` that the app ignores.
    """
    email, _, rest = issued["email"].partition("&role=admin&z=")
    leftover = rest + "&role=" + issued["role"]
    return {"email": email, "role": "admin", "z": leftover, "sig": issued["sig"]}
