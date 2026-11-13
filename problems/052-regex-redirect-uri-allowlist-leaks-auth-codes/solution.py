"""OAuth redirect_uri validation by exact match instead of regular expressions.

The authorization server let client apps register redirect URIs as regex
patterns and checked them with `re.match`. Unescaped dots matched any
character ("app.example.com" also matched "appxexample.com"), `.*` used for
"any subdomain" also matched across the host into the path, and `re.match`
only anchors at the start. Attackers registered lookalike domains and received
users' authorization codes. This version compares the parsed URI against a
list of exactly registered URIs, as OAuth 2.1 and RFC 9700 require.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_PORTS = {"https": 443}
ALLOWED_SCHEMES = ("https",)


def naive_is_allowed(redirect_uri: str, registered_patterns: list[str]) -> bool:
    """Original check: any registered regex that matches the start of the URI."""
    for pattern in registered_patterns:
        if re.match(pattern, redirect_uri):
            return True
    return False


@dataclass(frozen=True)
class RedirectTarget:
    """The parts of a redirect URI that decide where the code is delivered."""
    scheme: str
    host: str
    port: int
    path: str
    query: str


def parse_redirect_uri(uri: str) -> RedirectTarget | None:
    """Parse a URI into a comparable form, or None if it must never be accepted.

    Userinfo ("user@host") and fragments are refused outright: userinfo is a
    classic way to make a URL look like it points somewhere else, and RFC 6749
    forbids fragments in redirect URIs.
    """
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ALLOWED_SCHEMES:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if parts.fragment or "#" in uri:
        return None
    if not parts.hostname:
        return None
    # Hostnames are case-insensitive and "https://h" equals "https://h:443".
    effective_port = port if port is not None else DEFAULT_PORTS[parts.scheme]
    return RedirectTarget(parts.scheme, parts.hostname.lower(), effective_port, parts.path or "/", parts.query)


def is_allowed(redirect_uri: str, registered_uris: list[str]) -> bool:
    """True only if the URI is exactly one of the client's registered URIs.

    Comparison is on parsed parts, so harmless differences (host case, an
    explicit default port) do not matter, but any difference in host or
    path does.
    """
    requested = parse_redirect_uri(redirect_uri)
    if requested is None:
        return False
    for registered in registered_uris:
        if parse_redirect_uri(registered) == requested:
            return True
    return False
