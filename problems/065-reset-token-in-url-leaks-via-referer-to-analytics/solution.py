"""Keep password-reset tokens out of the Referer header.

The reset page was served at ``/reset?token=...`` with ``Referrer-Policy:
unsafe-url`` and loaded a third-party analytics script, a chat widget and a
tracking pixel. Every one of those requests carried the full page URL, token
included, in its ``Referer`` header, so the vendors' logs held live reset
tokens that anyone with log access could use to take over accounts.

The fix has two parts. ``referer_for`` models how a browser computes the
Referer for each Referrer-Policy (W3C Referrer Policy spec), which the tests
use to show what leaks. ``ResetService`` exchanges the emailed token for a
short-lived, single-use, HttpOnly session cookie and 303-redirects to a
token-free ``/reset`` page served with ``Referrer-Policy: no-referrer`` and
no third-party resources.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit, urlunsplit

POLICIES = ("no-referrer", "no-referrer-when-downgrade", "same-origin", "origin",
            "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin",
            "unsafe-url")
# Default in current browsers when no valid policy is given.
DEFAULT_POLICY = "strict-origin-when-cross-origin"
MAX_REFERRER_LENGTH = 4096
DEFAULT_PORTS = {"http": 80, "https": 443}
SITE = "https://accounts.shop.example"
THIRD_PARTY_RESOURCES = ("https://cdn.analytics.example/tag.js",
                         "https://widget.chat.example/loader.js",
                         "https://pixel.ads.example/p.gif")
SAME_ORIGIN_RESOURCES = (f"{SITE}/static/reset.js", f"{SITE}/static/logo.png")
TOKEN_TTL_SECONDS = 30 * 60
SESSION_TTL_SECONDS = 10 * 60
SESSION_COOKIE = "reset_session"


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    subresources: tuple[str, ...] = ()
    body: str = ""


@dataclass
class FakeClock:
    now: float = 0.0


Origin = tuple[str, str, int]


def origin_of(url: str) -> Origin:
    """(scheme, host, port) with the default port filled in."""
    parts = urlsplit(url)
    port = parts.port or DEFAULT_PORTS.get(parts.scheme, 0)
    return parts.scheme, parts.hostname or "", port


def is_trustworthy(url: str) -> bool:
    """Simplified "potentially trustworthy URL": HTTPS/WSS or loopback."""
    parts = urlsplit(url)
    host = parts.hostname or ""
    return parts.scheme in ("https", "wss") or host == "localhost" or host.startswith("127.")


def strip_for_referrer(url: str, origin_only: bool) -> str:
    """Drop userinfo and fragment always; drop path and query for origin-only."""
    scheme, host, port = origin_of(url)
    netloc = host if port == DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    if origin_only:
        return urlunsplit((scheme, netloc, "/", "", ""))
    parts = urlsplit(url)
    return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))


def referer_for(page_url: str, request_url: str, policy: str) -> str | None:
    """The Referer a browser sends from page_url to request_url, or None."""
    full = strip_for_referrer(page_url, origin_only=False)
    origin = strip_for_referrer(page_url, origin_only=True)
    # Spec: an over-long referrer is cut to its origin before the policy runs.
    if len(full) > MAX_REFERRER_LENGTH:
        full = origin
    same_origin = origin_of(page_url) == origin_of(request_url)
    downgrade = is_trustworthy(page_url) and not is_trustworthy(request_url)
    if policy == "no-referrer":
        return None
    if policy == "unsafe-url":
        return full
    if policy == "origin":
        return origin
    if policy == "same-origin":
        return full if same_origin else None
    if policy == "no-referrer-when-downgrade":
        return None if downgrade else full
    if policy == "strict-origin":
        return None if downgrade else origin
    if policy == "origin-when-cross-origin":
        return full if same_origin else origin
    # strict-origin-when-cross-origin
    if same_origin:
        return full
    return None if downgrade else origin


def parse_policy_header(header: str | None) -> str:
    """Last recognised token wins (lets sites list fallbacks for old browsers)."""
    chosen = DEFAULT_POLICY
    for token in (header or "").split(","):
        token = token.strip().lower()
        if token in POLICIES:
            chosen = token
    return chosen


def outgoing_requests(page_url: str, response: Response) -> list[tuple[str, str | None]]:
    """(resource URL, Referer) for every subresource the page loads."""
    policy = parse_policy_header(response.headers.get("Referrer-Policy"))
    return [(url, referer_for(page_url, url, policy)) for url in response.subresources]


def naive_reset_page(page_url: str) -> Response:
    """The original page: token stays in the URL, vendors' scripts load."""
    return Response(200, {"Referrer-Policy": "unsafe-url"},
                    THIRD_PARTY_RESOURCES + SAME_ORIGIN_RESOURCES, "Choose a new password")


def hash_secret(value: str) -> str:
    """Store only hashes, so a database leak does not hand out live tokens."""
    return hashlib.sha256(value.encode()).hexdigest()


class ResetService:
    """Fixed flow: token -> one-time cookie session -> token-free page."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.tokens: dict[str, tuple[str, float]] = {}      # hash -> (email, expiry)
        self.sessions: dict[str, tuple[str, float]] = {}    # hash -> (email, expiry)
        self.passwords: dict[str, str] = {}

    def issue_token(self, email: str) -> str:
        """Create the emailed token; only its hash is kept."""
        token = secrets.token_urlsafe(32)
        self.tokens[hash_secret(token)] = (email, self.clock.now + TOKEN_TTL_SECONDS)
        return token

    def reset_link(self, token: str) -> str:
        """The link in the email points at the exchange endpoint, not the form."""
        return f"{SITE}/reset/start?token={token}"

    def start(self, url: str) -> Response:
        """GET /reset/start: swap the token for a cookie and redirect away."""
        token = parse_qs(urlsplit(url).query).get("token", [""])[0]
        # pop() makes the token single-use whether or not it is still valid.
        record = self.tokens.pop(hash_secret(token), None)
        if record is None or record[1] <= self.clock.now:
            return Response(400, {"Referrer-Policy": "no-referrer"}, body="Link expired")
        session_id = secrets.token_urlsafe(32)
        self.sessions[hash_secret(session_id)] = (record[0], self.clock.now + SESSION_TTL_SECONDS)
        cookie = (f"{SESSION_COOKIE}={session_id}; Path=/reset; Max-Age={SESSION_TTL_SECONDS}; "
                  "HttpOnly; Secure; SameSite=Strict")
        # 303 so the browser issues a fresh GET to a URL without the token.
        return Response(303, {"Location": f"{SITE}/reset", "Set-Cookie": cookie,
                              "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"})

    def _session_email(self, cookies: dict[str, str]) -> str | None:
        """The email for a valid, unexpired reset session cookie."""
        record = self.sessions.get(hash_secret(cookies.get(SESSION_COOKIE, "")))
        if record is None or record[1] <= self.clock.now:
            return None
        return record[0]

    def form(self, cookies: dict[str, str]) -> Response:
        """GET /reset: the form, with no token in the URL and no vendor scripts."""
        if self._session_email(cookies) is None:
            return Response(403, {"Referrer-Policy": "no-referrer"}, body="Start again")
        return Response(200, {"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"},
                        SAME_ORIGIN_RESOURCES, "Choose a new password")

    def submit(self, cookies: dict[str, str], new_password: str) -> bool:
        """POST /reset: set the password once, then the session is gone."""
        email = self._session_email(cookies)
        if email is None:
            return False
        del self.sessions[hash_secret(cookies[SESSION_COOKIE])]
        self.passwords[email] = hash_secret(new_password)  # real code: a slow password hash
        return True


def cookie_from(response: Response) -> dict[str, str]:
    """Parse the name=value pair out of a Set-Cookie header (enough for tests)."""
    name, _, value = response.headers["Set-Cookie"].split(";")[0].partition("=")
    return {name: value}
