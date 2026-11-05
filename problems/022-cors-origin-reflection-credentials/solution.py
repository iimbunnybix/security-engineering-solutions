"""CORS policy that only trusts exact, allowlisted origins.

The account API answered every cross-origin request by copying the
request's Origin header into Access-Control-Allow-Origin together with
Access-Control-Allow-Credentials: true. Any website a logged-in user visited
could therefore read their profile and API keys with fetch(). A later
"fix" used endswith("example.com"), which also trusts evil-example.com.
This module parses each Origin into (scheme, host, port), compares it with
an allowlist of exact origins, never trusts "null", and always sends
Vary: Origin so caches do not serve one origin's answer to another.
"""
from __future__ import annotations

from typing import Iterable, NamedTuple
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}

# Browsers send the literal string "null" from sandboxed iframes, file://
# pages and some redirects. Anyone can produce it, so it is never trusted.
OPAQUE_ORIGIN = "null"


class Origin(NamedTuple):
    scheme: str
    host: str
    port: int

    def serialise(self) -> str:
        """Canonical text form, omitting the port when it is the default."""
        if DEFAULT_PORTS[self.scheme] == self.port:
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"


def naive_cors_headers(request_origin: str | None) -> dict[str, str]:
    """Original behaviour: reflect whatever Origin the browser sent."""
    if not request_origin:
        return {}
    return {
        "Access-Control-Allow-Origin": request_origin,
        "Access-Control-Allow-Credentials": "true",
    }


def naive_suffix_check(request_origin: str, trusted_domain: str) -> bool:
    """First attempted fix: a string suffix test. Trusts evil-example.com."""
    return request_origin.endswith(trusted_domain)


def naive_substring_check(request_origin: str, trusted_domain: str) -> bool:
    """Second attempted fix: a substring test. Trusts example.com.attacker.net."""
    return trusted_domain in request_origin


def parse_origin(text: str) -> Origin | None:
    """Parse an Origin header value, or return None if it is not a valid origin.

    A valid origin is exactly scheme://host[:port] - no path, query,
    fragment or user info. Anything else is rejected rather than "cleaned
    up", because lenient parsing is how allowlist checks get bypassed.
    """
    if not text or text == OPAQUE_ORIGIN or text.strip() != text:
        return None
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        return None
    if parts.path or parts.query or parts.fragment or "@" in parts.netloc:
        return None
    if not parts.hostname:
        return None
    if port is None:
        port = DEFAULT_PORTS[scheme]
    return Origin(scheme, parts.hostname.lower().rstrip("."), port)


class CorsPolicy:
    """Decides the CORS response headers for one API."""

    def __init__(self, allowed_origins: Iterable[str]) -> None:
        self.allowed: set[Origin] = set()
        for text in allowed_origins:
            origin = parse_origin(text)
            # Fail at startup on a typo instead of silently trusting nothing.
            if origin is None:
                raise ValueError(f"invalid allowlist entry {text!r}")
            self.allowed.add(origin)

    def is_allowed(self, request_origin: str | None) -> bool:
        """True only if the origin exactly matches an allowlisted origin."""
        if request_origin is None:
            return False
        origin = parse_origin(request_origin)
        return origin is not None and origin in self.allowed

    def cors_headers(self, request_origin: str | None) -> dict[str, str]:
        """Headers to add to the response for this request's Origin.

        Vary: Origin is sent even on refusals: otherwise a shared cache may
        store the refusal (or an allowed answer) and replay it to a
        request from a different origin.
        """
        headers = {"Vary": "Origin"}
        if not self.is_allowed(request_origin):
            return headers
        canonical = parse_origin(request_origin).serialise()
        headers["Access-Control-Allow-Origin"] = canonical
        headers["Access-Control-Allow-Credentials"] = "true"
        return headers


def browser_lets_page_read_response(page_origin: str, headers: dict[str, str]) -> bool:
    """Simplified browser check for a credentialed fetch() from page_origin.

    The page may read the response only if Allow-Origin equals its origin
    exactly and credentials are explicitly allowed.
    """
    return (headers.get("Access-Control-Allow-Origin") == page_origin
            and headers.get("Access-Control-Allow-Credentials") == "true")
