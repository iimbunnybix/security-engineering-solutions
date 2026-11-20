"""Bind mobile OAuth authorization codes to the app that asked for them (PKCE).

The mobile app is a public client (no client secret) and receives its
authorization code on the custom URL scheme ``myapp://callback``. A malicious
app registered the same scheme, so the phone sometimes handed it the code, and
the naive authorization server exchanged any code for tokens without asking
who was presenting it.

The fix is PKCE (RFC 7636) with the S256 method: the real app sends
``code_challenge = BASE64URL(SHA256(code_verifier))`` when it starts the flow
and must prove it knows ``code_verifier`` when it exchanges the code. The
server rejects the "plain" method and missing verifiers, and codes are
single-use and expire after 60 seconds.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import string
from dataclasses import dataclass

VERIFIER_MIN_LENGTH = 43
VERIFIER_MAX_LENGTH = 128
UNRESERVED_CHARACTERS = frozenset(string.ascii_letters + string.digits + "-._~")
# 64 random bytes -> 86 base64url characters, well inside 43..128.
VERIFIER_RANDOM_BYTES = 64
S256_CHALLENGE_LENGTH = 43  # 32-byte SHA-256 digest, base64url without padding
CODE_TTL_SECONDS = 60
CLIENT_ID = "shop-mobile-app"
REDIRECT_URI = "myapp://callback"


class OAuthError(Exception):
    """An OAuth error response; ``code`` is the RFC 6749 error string."""

    def __init__(self, code: str, description: str) -> None:
        super().__init__(f"{code}: {description}")
        self.code = code


@dataclass
class FakeClock:
    now: float = 0.0


@dataclass(frozen=True)
class CodeGrant:
    user: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    expires_at: float


def new_token() -> str:
    """Random opaque token generated at runtime (never a literal)."""
    return secrets.token_urlsafe(32)


class NaiveAuthServer:
    """The original server: any holder of a code can exchange it."""

    def __init__(self) -> None:
        self.codes: dict[str, tuple[str, str]] = {}  # code -> (user, redirect_uri)

    def authorize(self, user: str, client_id: str, redirect_uri: str) -> str:
        """User approved the app; return the redirect carrying the code."""
        code = new_token()
        self.codes[code] = (user, redirect_uri)
        return f"{redirect_uri}?code={code}"

    def exchange(self, code: str, client_id: str, redirect_uri: str) -> dict[str, str]:
        """Token endpoint: no client secret and no proof of who started the flow."""
        user, expected_redirect = self.codes[code]
        if redirect_uri != expected_redirect:
            raise OAuthError("invalid_grant", "redirect_uri mismatch")
        return {"access_token": new_token(), "user": user}


def generate_code_verifier() -> str:
    """High-entropy verifier from the unreserved character set."""
    return secrets.token_urlsafe(VERIFIER_RANDOM_BYTES)


def is_valid_verifier(verifier: str) -> bool:
    """RFC 7636 section 4.1: 43-128 characters, unreserved characters only."""
    if not VERIFIER_MIN_LENGTH <= len(verifier) <= VERIFIER_MAX_LENGTH:
        return False
    return all(char in UNRESERVED_CHARACTERS for char in verifier)


def s256_challenge(verifier: str) -> str:
    """BASE64URL(SHA256(ASCII(verifier))) with the '=' padding removed."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def hash_code(code: str) -> str:
    """Codes are stored hashed so a database read does not yield live codes."""
    return hashlib.sha256(code.encode()).hexdigest()


class PkceAuthServer:
    """Fixed server: S256 PKCE required, codes single-use and short-lived."""

    def __init__(self, clock: FakeClock, registered_redirects: dict[str, str]) -> None:
        self.clock = clock
        self.registered_redirects = registered_redirects
        self.grants: dict[str, CodeGrant] = {}

    def authorize(self, user: str, client_id: str, redirect_uri: str,
                  code_challenge: str | None, method: str | None) -> str:
        """Authorization endpoint: refuse to issue a code without an S256 challenge."""
        if self.registered_redirects.get(client_id) != redirect_uri:
            raise OAuthError("invalid_request", "unregistered redirect_uri")
        if not code_challenge:
            raise OAuthError("invalid_request", "code_challenge required")
        # "plain" sends the verifier itself, which the interceptor can also see.
        if method != "S256":
            raise OAuthError("invalid_request", "code_challenge_method must be S256")
        if len(code_challenge) != S256_CHALLENGE_LENGTH:
            raise OAuthError("invalid_request", "malformed code_challenge")
        code = new_token()
        self.grants[hash_code(code)] = CodeGrant(
            user, client_id, redirect_uri, code_challenge, self.clock.now + CODE_TTL_SECONDS)
        return f"{redirect_uri}?code={code}"

    def exchange(self, code: str, client_id: str, redirect_uri: str,
                 code_verifier: str | None) -> dict[str, str]:
        """Token endpoint: the presenter must know the verifier behind the challenge."""
        # pop() first: a code is burned by any attempt, right or wrong.
        grant = self.grants.pop(hash_code(code), None)
        if grant is None or grant.expires_at <= self.clock.now:
            raise OAuthError("invalid_grant", "unknown, used or expired code")
        if grant.client_id != client_id or grant.redirect_uri != redirect_uri:
            raise OAuthError("invalid_grant", "client or redirect_uri mismatch")
        if code_verifier is None:
            raise OAuthError("invalid_request", "code_verifier required")
        if not is_valid_verifier(code_verifier):
            raise OAuthError("invalid_grant", "malformed code_verifier")
        # Constant-time compare so timing does not reveal how much matched.
        if not hmac.compare_digest(s256_challenge(code_verifier), grant.code_challenge):
            raise OAuthError("invalid_grant", "code_verifier does not match")
        return {"access_token": new_token(), "user": grant.user}


def code_from_redirect(redirect_url: str) -> str:
    """Pull the code out of myapp://callback?code=..."""
    return redirect_url.split("code=", 1)[1]
