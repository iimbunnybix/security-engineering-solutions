"""Validate the post-login ``next`` parameter so it cannot send users off-site.

The login page accepts ``?next=<url>`` and redirects there after a successful
sign-in. The original check only required the value to start with ``/``,
intending "relative paths only". Browsers, however, interpret several values
that start with ``/`` as links to *another host*:

* ``//evil.example/login``           scheme-relative URL
* ``/\\evil.example``                 backslash treated as a slash
* ``/\\t/evil.example``               tab/newline characters are stripped

and ``javascript:`` URLs run script in our origin.

``safe_redirect_target`` parses the value the way a browser would, allows only
same-site paths or an explicit allow-list of hosts over https, and otherwise
falls back to a default page.
"""
from __future__ import annotations

from typing import Iterable, Optional
from urllib.parse import quote, urlsplit, urlunsplit

DEFAULT_TARGET = "/dashboard"
MAX_LENGTH = 2048
# C0 controls, DEL and C1 controls have no legitimate use in a redirect target.
C0_CONTROL_LIMIT = 0x20
DEL = 0x7F
C1_CONTROL_RANGE = range(0x80, 0xA0)


def naive_redirect_target(next_url: Optional[str]) -> str:
    """Original check: 'starts with a slash means it's a local path'."""
    if next_url and next_url.startswith("/"):
        return next_url
    return DEFAULT_TARGET


def _browser_normalize(value: str) -> str:
    """Mimic the WHATWG URL parser's leniency before we parse.

    Browsers strip leading/trailing C0 control characters and spaces, remove
    tab/CR/LF anywhere in the URL, and treat ``\\`` like ``/`` for http(s)
    and scheme-relative URLs.
    """
    value = value.strip("".join(chr(c) for c in range(0x21)))
    value = value.replace("\t", "").replace("\r", "").replace("\n", "")
    return value.replace("\\", "/")


def _is_control_character(ch: str) -> bool:
    """True for C0 controls, DEL and C1 controls (e.g. U+0085 NEL)."""
    code = ord(ch)
    return code < C0_CONTROL_LIMIT or code == DEL or code in C1_CONTROL_RANGE


def _encode_non_ascii(text: str) -> str:
    """Percent-encode every non-ASCII character as UTF-8, keep ASCII as-is.

    HTTP header values are bytes (Latin-1 in WSGI), so a raw character such as
    U+2028 would crash the response after the user already logged in. Encoding
    only non-ASCII characters leaves existing ``%XX`` escapes untouched.
    """
    pieces = []
    for ch in text:
        pieces.append(ch if ch.isascii() else quote(ch, safe=""))
    return "".join(pieces)


def _rebuild(scheme: str, host: str, path: str, query: str, fragment: str) -> str:
    """Join the validated parts into an ASCII-only ``Location`` value."""
    return urlunsplit((scheme, host, _encode_non_ascii(path),
                       _encode_non_ascii(query), _encode_non_ascii(fragment)))


def safe_redirect_target(next_url: Optional[str], allowed_hosts: Iterable[str] = (),
                         default: str = DEFAULT_TARGET) -> str:
    """Return ``next_url`` if it is safe to redirect to, else ``default``.

    Safe means either:
    * a path on this site: starts with exactly one ``/``, no scheme, no host; or
    * an absolute ``https`` URL whose host is in ``allowed_hosts`` (exact match,
      no user-info, default port).

    The returned value is rebuilt from the parsed parts (non-ASCII characters
    percent-encoded), so what we validated is exactly what we send in the
    ``Location`` header and it is always ASCII.
    """
    if not next_url or len(next_url) > MAX_LENGTH:
        return default
    if any(_is_control_character(ch) for ch in next_url.strip()):
        # control characters inside the value have no legitimate use here
        return default
    value = _browser_normalize(next_url)
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return default

    allowed = {h.lower().rstrip(".") for h in allowed_hosts}

    if not parts.scheme and not parts.netloc:
        if not value.startswith("/") or value.startswith("//"):
            return default            # "evil.example" or "//evil" style
        return _rebuild("", "", parts.path, parts.query, parts.fragment)

    if parts.scheme != "https" or not parts.netloc:
        return default                # javascript:, data:, http:, ftp:, //host...
    if parts.username is not None or parts.password is not None:
        return default                # https://app.example.com@evil.example
    host = (parts.hostname or "").rstrip(".")
    if host not in allowed or port not in (None, 443):
        return default
    return _rebuild("https", host, parts.path or "/", parts.query, parts.fragment)
