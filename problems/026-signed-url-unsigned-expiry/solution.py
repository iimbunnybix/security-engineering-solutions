"""Signed download links whose expiry time cannot be edited by the user.

Invoices are shared as links like ``/files/inv-17.pdf?expires=...&sig=...``.
The original code signed only the file path. The ``expires`` value was
checked against the clock but was not part of the signature, so anyone with
an expired link could change ``expires`` to a date in 2099 and the link
worked again, forever. Leaked links in old emails and chat logs never died.

The fix signs a canonical string that contains every field the server
relies on (method, path and expiry), parses the query strictly (exactly one
value per parameter, no unknown parameters) and compares signatures in
constant time.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Callable
from urllib.parse import parse_qs, quote, unquote, urlsplit

Clock = Callable[[], int]

MAX_LINK_LIFETIME_S = 7 * 24 * 3600
ALLOWED_PARAMS = {"expires", "sig"}


class InvalidLink(Exception):
    """The link is malformed, tampered with, or expired."""


def hmac_hex(key: bytes, message: str) -> str:
    """HMAC-SHA256 of ``message`` as hex."""
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


# --- original version ---------------------------------------------------
def naive_sign(key: bytes, path: str, expires: int) -> str:
    """The bug: ``expires`` is in the URL but not in the signature."""
    return f"{quote(path)}?expires={expires}&sig={hmac_hex(key, path)}"


def naive_verify(key: bytes, url: str, now: int) -> str:
    """Return the path if the link is valid (by the original rules)."""
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    path = parts.path
    if not hmac.compare_digest(query["sig"][0], hmac_hex(key, path)):
        raise InvalidLink("bad signature")
    if int(query["expires"][0]) < now:
        raise InvalidLink("expired")
    return path


# --- fixed version ------------------------------------------------------
def canonical_string(method: str, path: str, expires: int) -> str:
    """Everything the server trusts from the link, in one unambiguous string.

    Fields are joined with newlines, and paths containing a newline are
    rejected, so two different links can never produce the same string.
    """
    if "\n" in path:
        raise InvalidLink("path must not contain a newline")
    return f"v1\n{method}\n{path}\n{expires}"


def sign_link(key: bytes, path: str, now: int, lifetime_s: int, method: str = "GET") -> str:
    """Create a link that is valid for ``lifetime_s`` seconds from ``now``."""
    if not 0 < lifetime_s <= MAX_LINK_LIFETIME_S:
        raise ValueError(f"lifetime must be 1..{MAX_LINK_LIFETIME_S} seconds")
    expires = now + lifetime_s
    signature = hmac_hex(key, canonical_string(method, path, expires))
    return f"{quote(path)}?expires={expires}&sig={signature}"


def strict_query(query_string: str) -> dict[str, str]:
    """Parse the query: only known parameters, each exactly once."""
    parsed = parse_qs(query_string, keep_blank_values=True, strict_parsing=bool(query_string))
    if set(parsed) != ALLOWED_PARAMS:
        raise InvalidLink(f"link must have exactly the parameters {sorted(ALLOWED_PARAMS)}")
    single_values = {}
    for name, values in parsed.items():
        # Duplicate parameters are a classic way to make the signer and
        # the verifier look at different values.
        if len(values) != 1:
            raise InvalidLink(f"parameter {name!r} must appear once")
        single_values[name] = values[0]
    return single_values


def parse_expires(raw: str) -> int:
    """Expiry must be plain digits (no sign, spaces or decimals)."""
    if not raw.isascii() or not raw.isdigit():
        raise InvalidLink("expires must be a whole number of seconds")
    return int(raw)


def verify_link(key: bytes, url: str, now: int, method: str = "GET") -> str:
    """Return the file path if the link is authentic and unexpired."""
    parts = urlsplit(url)
    try:
        query = strict_query(parts.query)
    except ValueError as error:
        raise InvalidLink(str(error)) from error
    expires = parse_expires(query["expires"])
    # The link carries the percent-encoded path; sign and compare the
    # decoded form, which is also what the file lookup will use.
    path = unquote(parts.path)
    expected = hmac_hex(key, canonical_string(method, path, expires))
    # Check the signature before trusting any field, in constant time.
    if not hmac.compare_digest(query["sig"].encode("ascii", "replace"), expected.encode("ascii")):
        raise InvalidLink("bad signature")
    if now >= expires:
        raise InvalidLink("expired")
    return path
