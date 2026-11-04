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
from urllib.parse import urlsplit, urlunsplit

DEFAULT_TARGET = "/dashboard"
MAX_LENGTH = 2048


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


def safe_redirect_target(next_url: Optional[str], allowed_hosts: Iterable[str] = (),
                         default: str = DEFAULT_TARGET) -> str:
    """Return ``next_url`` if it is safe to redirect to, else ``default``.

    Safe means either:
    * a path on this site: starts with exactly one ``/``, no scheme, no host; or
    * an absolute ``https`` URL whose host is in ``allowed_hosts`` (exact match,
      no user-info, default port).

    The returned value is rebuilt from the parsed parts, so what we validated
    is exactly what we send in the ``Location`` header.
    """
    if not next_url or len(next_url) > MAX_LENGTH:
        return default
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in next_url.strip()):
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
        return urlunsplit(("", "", parts.path, parts.query, parts.fragment))

    if parts.scheme != "https" or not parts.netloc:
        return default                # javascript:, data:, http:, ftp:, //host...
    if parts.username is not None or parts.password is not None:
        return default                # https://app.example.com@evil.example
    host = (parts.hostname or "").rstrip(".")
    if host not in allowed or port not in (None, 443):
        return default
    return urlunsplit(("https", host, parts.path or "/", parts.query, parts.fragment))
