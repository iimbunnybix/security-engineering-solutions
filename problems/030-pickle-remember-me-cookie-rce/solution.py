"""Replace a pickled "remember me" cookie with signed, schema-checked JSON.

The original web app stored the remember-me data (user id, theme, expiry)
as ``base64(pickle.dumps(dict))`` in a cookie and called ``pickle.loads`` on
whatever came back. Unpickling runs code chosen by the data (``__reduce__``),
so anyone could send a cookie that executed commands on the web server.

The fix serializes with JSON, which can only produce plain data, signs it
with HMAC-SHA256, checks the signature before parsing anything, and accepts
only an exact schema: known keys, right types, allowed values, not expired.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import pickle
from dataclasses import dataclass
from typing import Callable

Clock = Callable[[], float]

MAX_COOKIE_LENGTH = 4096            # browsers cap a cookie at about 4 KB anyway
REMEMBER_ME_TTL_S = 30 * 24 * 3600
ALLOWED_THEMES = frozenset({"light", "dark"})
MAX_USER_ID_LENGTH = 64
SEPARATOR = "."


class InvalidCookie(Exception):
    """The cookie is malformed, forged, expired or does not fit the schema."""


@dataclass(frozen=True)
class RememberMe:
    user_id: str
    theme: str
    expires_at: int


# --- original version ---------------------------------------------------
def naive_encode(data: dict) -> str:
    """The bug, part 1: pickle the preferences into the cookie."""
    return base64.urlsafe_b64encode(pickle.dumps(data)).decode()


def naive_decode(cookie: str) -> dict:
    """The bug, part 2: unpickle untrusted bytes, which can run any code."""
    return pickle.loads(base64.urlsafe_b64decode(cookie))


# --- fixed version ------------------------------------------------------
def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64decode(text: str) -> bytes:
    """Decode unpadded base64url; any malformed input becomes InvalidCookie."""
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as error:
        raise InvalidCookie("bad base64") from error


def _sign(key: bytes, body: str) -> str:
    return _b64encode(hmac.new(key, body.encode(), hashlib.sha256).digest())


def issue_cookie(key: bytes, user_id: str, theme: str, clock: Clock) -> str:
    """Create a remember-me cookie: base64url(JSON) "." base64url(HMAC)."""
    payload = {"user_id": user_id, "theme": theme,
               "expires_at": int(clock()) + REMEMBER_ME_TTL_S}
    # Validate our own output too, so we never issue a cookie we would reject.
    _check_schema(payload)
    body = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    return body + SEPARATOR + _sign(key, body)


def _verified_body(key: bytes, cookie: str) -> bytes:
    """Return the JSON bytes only if the HMAC over them is correct."""
    if len(cookie) > MAX_COOKIE_LENGTH or cookie.count(SEPARATOR) != 1:
        raise InvalidCookie("malformed cookie")
    body, signature = cookie.split(SEPARATOR)
    # WHY first: nothing attacker-made is parsed until we know we wrote it.
    if not hmac.compare_digest(_sign(key, body), signature):
        raise InvalidCookie("bad signature")
    return _b64decode(body)


def _check_schema(payload: object) -> RememberMe:
    """Accept exactly {user_id: str, theme: allowed str, expires_at: int}."""
    if not isinstance(payload, dict) or set(payload) != {"user_id", "theme", "expires_at"}:
        raise InvalidCookie("unexpected fields")
    user_id, theme, expires_at = payload["user_id"], payload["theme"], payload["expires_at"]
    if not isinstance(user_id, str) or not 0 < len(user_id) <= MAX_USER_ID_LENGTH:
        raise InvalidCookie("bad user_id")
    if theme not in ALLOWED_THEMES:
        raise InvalidCookie("bad theme")
    # bool is a subclass of int in Python; true/false is not a timestamp.
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise InvalidCookie("bad expires_at")
    return RememberMe(user_id, theme, expires_at)


def read_cookie(key: bytes, cookie: str, clock: Clock) -> RememberMe:
    """Verify, parse and validate a remember-me cookie, or raise InvalidCookie."""
    body = _verified_body(key, cookie)
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError) as error:
        raise InvalidCookie("not JSON") from error
    remember = _check_schema(payload)
    if clock() >= remember.expires_at:
        raise InvalidCookie("expired")
    return remember
