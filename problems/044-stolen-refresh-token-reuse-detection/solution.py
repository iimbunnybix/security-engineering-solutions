"""Refresh token rotation with reuse detection.

The mobile app's refresh token was valid for 30 days and could be used any
number of times. A token copied off a phone therefore gave the thief fresh
access tokens for a month, and nothing on the server could tell the thief's
refreshes apart from the owner's.

The fix rotates: every refresh returns a NEW refresh token and marks the old
one as used. Tokens issued from one login form a "family". If a used token is
presented again, two parties hold copies of the same token, so the whole
family (every refresh and access token from that login) is revoked and the
user must log in again. Only SHA-256 digests of tokens are stored.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from typing import Callable

MINUTE = 60
DAY = 24 * 60 * MINUTE
ACCESS_TOKEN_TTL_SECONDS = 15 * MINUTE
REFRESH_TOKEN_TTL_SECONDS = 30 * DAY
# A family cannot be refreshed forever: after this the user logs in again.
FAMILY_MAX_LIFETIME_SECONDS = 90 * DAY
TOKEN_BYTES = 32

Clock = Callable[[], float]
TokenFactory = Callable[[], str]


def random_token() -> str:
    """Production token source: 256 bits from the OS random generator."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_digest(token: str) -> str:
    """What the database stores. Tokens are random, so a fast hash suffices."""
    return hashlib.sha256(token.encode()).hexdigest()


class InvalidRefreshToken(Exception):
    """Unknown, expired or revoked refresh token: the client must log in."""


class RefreshTokenReuse(InvalidRefreshToken):
    """A rotated-out token came back: the family has been revoked."""


@dataclass(frozen=True)
class TokenPair:
    access_token: str
    refresh_token: str


class NaiveRefreshStore:
    """ORIGINAL: one long-lived refresh token, reusable until it expires."""

    def __init__(self, clock: Clock, new_token: TokenFactory = random_token) -> None:
        self._clock = clock
        self._new_token = new_token
        self._refresh: dict[str, tuple[str, float]] = {}   # token -> (user, expires)

    def login(self, user: str) -> TokenPair:
        """Issue an access token and a 30-day refresh token."""
        refresh_token = self._new_token()
        expires_at = self._clock() + REFRESH_TOKEN_TTL_SECONDS
        self._refresh[refresh_token] = (user, expires_at)
        return TokenPair(self._new_token(), refresh_token)

    def refresh(self, refresh_token: str) -> TokenPair:
        """Return a new access token; the SAME refresh token stays valid."""
        record = self._refresh.get(refresh_token)
        if record is None or self._clock() >= record[1]:
            raise InvalidRefreshToken("log in again")
        return TokenPair(self._new_token(), refresh_token)


@dataclass
class Family:
    """Everything issued from one login on one device."""
    user: str
    created_at: float
    revoked: bool = False


@dataclass
class RefreshRecord:
    family_id: str
    expires_at: float
    used: bool = False


@dataclass(frozen=True)
class AccessRecord:
    family_id: str
    expires_at: float


class RotatingRefreshStore:
    """FIX: single-use refresh tokens; reuse revokes the whole family."""

    def __init__(self, clock: Clock, new_token: TokenFactory = random_token) -> None:
        self._clock = clock
        self._new_token = new_token
        self._families: dict[str, Family] = {}
        self._refresh: dict[str, RefreshRecord] = {}    # digest -> record
        self._access: dict[str, AccessRecord] = {}      # digest -> record

    def login(self, user: str) -> TokenPair:
        """Start a new family (call after the password/MFA check succeeds)."""
        family_id = self._new_token()
        self._families[family_id] = Family(user, self._clock())
        return self._issue_pair(family_id)

    def refresh(self, refresh_token: str) -> TokenPair:
        """Swap a refresh token for a new pair; the old token is used up."""
        record = self._refresh.get(token_digest(refresh_token))
        if record is None:
            raise InvalidRefreshToken("unknown refresh token")
        family = self._families[record.family_id]
        if family.revoked:
            raise InvalidRefreshToken("session revoked")
        if record.used:
            # Only one party should ever hold an unused copy. A second use
            # means the token was copied; we cannot tell who is the owner,
            # so we end the session for both.
            family.revoked = True
            raise RefreshTokenReuse("refresh token reused; session revoked")
        if self._is_expired(record, family):
            raise InvalidRefreshToken("refresh token expired")
        record.used = True
        return self._issue_pair(record.family_id)

    def authenticate(self, access_token: str) -> str | None:
        """Return the user for a live access token, else None."""
        record = self._access.get(token_digest(access_token))
        if record is None or self._clock() >= record.expires_at:
            return None
        family = self._families[record.family_id]
        if family.revoked:
            return None
        return family.user

    def stored_token_values(self) -> list[str]:
        """What a database dump would show: digests only."""
        return list(self._refresh) + list(self._access)

    def _is_expired(self, record: RefreshRecord, family: Family) -> bool:
        """Idle expiry of this token, or the family's absolute lifetime."""
        now = self._clock()
        if now >= record.expires_at:
            return True
        return now >= family.created_at + FAMILY_MAX_LIFETIME_SECONDS

    def _issue_pair(self, family_id: str) -> TokenPair:
        """Create and record a new access token and refresh token."""
        now = self._clock()
        access_token = self._new_token()
        refresh_token = self._new_token()
        self._access[token_digest(access_token)] = AccessRecord(
            family_id, now + ACCESS_TOKEN_TTL_SECONDS)
        self._refresh[token_digest(refresh_token)] = RefreshRecord(
            family_id, now + REFRESH_TOKEN_TTL_SECONDS)
        return TokenPair(access_token, refresh_token)
