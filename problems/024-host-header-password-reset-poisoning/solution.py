"""Password-reset links built from a trusted base URL, not the Host header.

The original "forgot password" handler built the reset link from the
request's ``X-Forwarded-Host`` / ``Host`` header. An attacker requested a
reset for the victim's email with ``Host: attacker.example``; the victim got
a genuine email whose link pointed at the attacker's site, and one click
handed the attacker the reset token.

``ResetService.request_reset`` builds links only from a configured canonical
base URL and refuses requests whose Host is not on an allowlist, so header
values never end up in an email.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from urllib.parse import urlsplit

TOKEN_BYTES = 32
RESET_PATH = "/reset-password"


@dataclass
class Request:
    headers: dict[str, str]
    form: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup, like real HTTP frameworks."""
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


@dataclass
class Email:
    to: str
    body: str


class Outbox:
    """Fake mail sender that records what would have been emailed."""

    def __init__(self) -> None:
        self.sent: list[Email] = []

    def send(self, to: str, body: str) -> None:
        self.sent.append(Email(to, body))


class InvalidHost(ValueError):
    """The request's Host header is not one of our own hostnames."""


def _issue_token(stored_hashes: dict[str, str], email: str) -> str:
    """Create a random token and store only its hash (a DB leak can't reuse it)."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
    stored_hashes[email] = hashlib.sha256(token.encode()).hexdigest()
    return token


def naive_request_reset(request: Request, users: set[str], tokens: dict[str, str],
                        outbox: Outbox) -> None:
    """The original handler: trusts X-Forwarded-Host / Host for the link."""
    email = request.form.get("email", "")
    if email not in users:
        return
    host = request.header("X-Forwarded-Host") or request.header("Host") or ""
    token = _issue_token(tokens, email)
    outbox.send(email, f"Reset your password: https://{host}{RESET_PATH}?token={token}")


def _normalise_host(raw_host: str) -> str:
    """Lower-case the host and drop a default :443 port for comparison."""
    host = raw_host.strip().lower()
    if host.endswith(":443"):
        host = host[: -len(":443")]
    return host


class ResetService:
    """Fixed reset flow: canonical link, Host allowlist, uniform response."""

    def __init__(self, base_url: str, allowed_hosts: set[str], users: set[str],
                 outbox: Outbox) -> None:
        parts = urlsplit(base_url)
        # The base URL is configuration, so fail at startup if it is not https.
        if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/"):
            raise ValueError("base_url must look like https://host")
        self.base_url = base_url.rstrip("/")
        self.allowed_hosts = {_normalise_host(host) for host in allowed_hosts}
        self.users = users
        self.outbox = outbox
        self.token_hashes: dict[str, str] = {}

    def check_host(self, request: Request) -> None:
        """Reject requests aimed at hostnames we do not serve.

        The link no longer uses the header, but an unknown Host is still a
        sign of probing or cache-poisoning attempts, so it is refused.
        """
        host = request.header("Host")
        if host is None or _normalise_host(host) not in self.allowed_hosts:
            raise InvalidHost(f"unexpected Host header: {host!r}")
        forwarded = request.header("X-Forwarded-Host")
        if forwarded is not None and _normalise_host(forwarded) not in self.allowed_hosts:
            raise InvalidHost(f"unexpected X-Forwarded-Host header: {forwarded!r}")

    def reset_link(self, token: str) -> str:
        """Build the link from configuration only."""
        return f"{self.base_url}{RESET_PATH}?token={token}"

    def request_reset(self, request: Request) -> str:
        """Email a reset link if the account exists; always return the same text."""
        self.check_host(request)
        email = request.form.get("email", "")
        if email in self.users:
            token = _issue_token(self.token_hashes, email)
            self.outbox.send(email, f"Reset your password: {self.reset_link(token)}")
        # Same reply either way, so the endpoint cannot be used to list accounts.
        return "If that account exists, we have emailed a reset link."
