"""CSRF protection for a cookie-authenticated web app.

The incident: the account-settings endpoint ``POST /account/email`` changed
the login email using only the session cookie for authentication. A page on
another site auto-submitted a hidden form to it; the victim's browser
attached the session cookie (the cookie was ``SameSite=None`` so a partner
iframe would work), the email was changed to the attacker's, and the
attacker then used "forgot password" to take over the account.

``CsrfProtection`` adds two independent checks to every unsafe request:

1. **Origin check** - ``Origin`` (or, if missing, ``Referer``) must be one of
   the app's own origins. Requests with neither header are rejected.
2. **Session-bound token** - an HMAC of the session id, sent in a form field
   or ``X-CSRF-Token`` header and compared in constant time. A token from
   another session, a forged one, or a missing one is rejected.

Safe methods (GET/HEAD/OPTIONS) are not checked; they must not change state.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class Request:
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    form: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


@dataclass
class Response:
    status: int
    body: str = ""


class SessionStore:
    """Minimal server-side sessions: session id -> user id."""

    def __init__(self) -> None:
        self._s: dict[str, str] = {}

    def login(self, user: str) -> str:
        sid = secrets.token_urlsafe(32)
        self._s[sid] = user
        return sid

    def user(self, req: Request) -> str | None:
        return self._s.get(req.cookies.get("session", ""))


def _origin_of(url: str) -> str | None:
    try:
        u = urlsplit(url)
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    default = {"http": 80, "https": 443}[u.scheme]
    port = u.port or default
    host = u.hostname.lower()
    return f"{u.scheme}://{host}" + ("" if port == default else f":{port}")


class CsrfProtection:
    def __init__(self, key: bytes, allowed_origins: set[str]):
        if len(key) < 32:
            raise ValueError("CSRF key must be at least 32 bytes")
        self._key = key
        self._origins = {_origin_of(o) for o in allowed_origins}
        if None in self._origins:
            raise ValueError("allowed_origins must be absolute http(s) origins")

    def token_for(self, session_id: str) -> str:
        """Token to embed in forms / return to the SPA for this session."""
        return hmac.new(self._key, b"csrf:" + session_id.encode(), hashlib.sha256).hexdigest()

    def check(self, req: Request) -> str | None:
        """Return a rejection reason, or None if the request may proceed."""
        if req.method.upper() in SAFE_METHODS:
            return None
        source = req.header("Origin")
        if source is None or source == "null":
            source = req.header("Referer")
        if not source:
            return "missing Origin/Referer"
        if _origin_of(source) not in self._origins:
            return "cross-origin request"
        sid = req.cookies.get("session")
        if not sid:
            return "no session"
        sent = req.header("X-CSRF-Token") or req.form.get("csrf_token") or ""
        if not hmac.compare_digest(sent.encode(), self.token_for(sid).encode()):
            return "bad CSRF token"
        return None


Handler = Callable[[Request], Response]


def protect(csrf: CsrfProtection, handler: Handler) -> Handler:
    def wrapped(req: Request) -> Response:
        reason = csrf.check(req)
        if reason:
            return Response(403, f"CSRF check failed: {reason}")
        return handler(req)
    return wrapped


class AccountApp:
    """Tiny app with the vulnerable and the fixed email-change endpoint."""

    def __init__(self, csrf: CsrfProtection):
        self.sessions = SessionStore()
        self.emails: dict[str, str] = {}
        self.csrf = csrf
        self.change_email_safe = protect(csrf, self.change_email_unsafe)

    def change_email_unsafe(self, req: Request) -> Response:
        user = self.sessions.user(req)
        if user is None:
            return Response(401, "login required")
        new = req.form.get("email", "")
        if "@" not in new:
            return Response(400, "invalid email")
        self.emails[user] = new
        return Response(200, "email updated")
