"""Stop other sites from loading our pages in an invisible frame (clickjacking).

The account settings page had a one-click "Delete account" button and sent
no framing headers. A malicious page loaded it in a transparent iframe over
a fake "Claim your prize" button; logged-in visitors who clicked the prize
button actually clicked "Delete account" on our site, with their own
cookies.

The fix adds ``Content-Security-Policy: frame-ancestors`` (and the older
``X-Frame-Options`` for old browsers) to every HTML response, merging into an
existing CSP instead of replacing it. ``can_be_framed`` models how a browser
applies those headers, so the tests check behaviour, not header strings.
"""
from __future__ import annotations

from urllib.parse import urlsplit

CSP_HEADER = "Content-Security-Policy"
XFO_HEADER = "X-Frame-Options"
SELF_SOURCE = "'self'"
NONE_SOURCE = "'none'"
DEFAULT_PORTS = {"http": 80, "https": 443}


def origin_of(url: str) -> tuple[str, str, int]:
    """(scheme, host, port) of a URL, with the default port filled in."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    port = parts.port or DEFAULT_PORTS.get(scheme, 0)
    return scheme, (parts.hostname or "").lower(), port


def frame_ancestors_sources(headers: dict[str, str]) -> list[str] | None:
    """Sources listed in the CSP frame-ancestors directive, or None if absent."""
    policy = headers.get(CSP_HEADER, "")
    for directive in policy.split(";"):
        tokens = directive.split()
        if tokens and tokens[0].lower() == "frame-ancestors":
            return tokens[1:]
    return None


def source_allows(source: str, embedder: str, page: str) -> bool:
    """Does one frame-ancestors source match the embedding page's origin?"""
    if source == "*":
        return True
    if source.lower() == SELF_SOURCE:
        return origin_of(embedder) == origin_of(page)
    return origin_of(source) == origin_of(embedder)


def can_be_framed(headers: dict[str, str], page_url: str, embedder_url: str) -> bool:
    """What a modern browser decides for <iframe src=page_url> on embedder_url."""
    sources = frame_ancestors_sources(headers)
    # When frame-ancestors is present, browsers ignore X-Frame-Options entirely.
    if sources is not None:
        if not sources or sources[0].lower() == NONE_SOURCE:
            return False
        return any(source_allows(source, embedder_url, page_url) for source in sources)
    option = headers.get(XFO_HEADER, "").strip().upper()
    if option == "DENY":
        return False
    if option == "SAMEORIGIN":
        return origin_of(embedder_url) == origin_of(page_url)
    # Missing, or values modern browsers do not support (ALLOW-FROM): no protection.
    return True


# --- the original, buggy version ---------------------------------------------
def naive_response_headers(existing: dict[str, str]) -> dict[str, str]:
    """Original middleware: no framing protection at all."""
    return dict(existing)


# --- the fix -----------------------------------------------------------------
def frame_ancestors_directive(allowed_embedders: list[str]) -> str:
    """'self' plus any explicitly allowed partner origins."""
    sources = [SELF_SOURCE]
    for embedder in allowed_embedders:
        scheme, host, port = origin_of(embedder)
        if scheme != "https" or not host:
            raise ValueError(f"embedder must be an https origin, got {embedder!r}")
        default = DEFAULT_PORTS[scheme]
        sources.append(f"https://{host}" if port == default else f"https://{host}:{port}")
    return "frame-ancestors " + " ".join(sources)


def merge_into_csp(existing_policy: str, directive: str) -> str:
    """Add or replace frame-ancestors while keeping every other CSP directive."""
    kept = []
    for part in existing_policy.split(";"):
        part = part.strip()
        if part and not part.lower().startswith("frame-ancestors"):
            kept.append(part)
    kept.append(directive)
    return "; ".join(kept)


def protected_response_headers(existing: dict[str, str],
                               allowed_embedders: list[str] | None = None) -> dict[str, str]:
    """Middleware for every HTML response, including error pages."""
    headers = dict(existing)
    directive = frame_ancestors_directive(allowed_embedders or [])
    headers[CSP_HEADER] = merge_into_csp(headers.get(CSP_HEADER, ""), directive)
    # For browsers too old for frame-ancestors. SAMEORIGIN cannot list partners,
    # but modern browsers use the CSP above and ignore this header.
    headers[XFO_HEADER] = "SAMEORIGIN"
    return headers
