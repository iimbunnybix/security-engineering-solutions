"""Unguessable, single-use, expiring password-reset tokens.

The original implementation derived the token from data an attacker knows or
can guess:

    token = md5(email + str(int(time.time()))).hexdigest()

An attacker requests a reset for the victim's email, notes the time of the
request, and tries the handful of tokens for the surrounding seconds. The
tokens were also stored in plaintext, never expired and could be reused.

``ResetTokenService`` fixes all of that:

* 256 bits from ``secrets.token_urlsafe`` (a CSPRNG), unrelated to user data;
* only a SHA-256 hash of the token is stored, so a database leak or a
  support-tool screenshot does not hand out working links;
* 30-minute expiry, single use, and a new request invalidates older tokens;
* lookups are by hash, and the final comparison uses ``hmac.compare_digest``.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional


# --------------------------------------------------------------------------
# Original implementation (kept to reproduce the attack)
# --------------------------------------------------------------------------
class NaiveResetService:
    def __init__(self, now: Callable[[], float]) -> None:
        self.now = now
        self.tokens: Dict[str, str] = {}          # token -> email, plaintext

    @staticmethod
    def make_token(email: str, timestamp: int) -> str:
        return hashlib.md5(f"{email}{timestamp}".encode()).hexdigest()

    def request_reset(self, email: str) -> str:
        token = self.make_token(email, int(self.now()))
        self.tokens[token] = email
        return token                               # emailed to the user

    def redeem(self, token: str) -> Optional[str]:
        return self.tokens.get(token)              # no expiry, reusable


def guess_naive_token(service: NaiveResetService, email: str, observed_time: float,
                      window: int = 5) -> Optional[tuple[str, int]]:
    """Attacker: try timestamps around when they triggered the reset.

    Returns (token, attempts) for the first token the service accepts.
    """
    attempts = 0
    base = int(observed_time)
    for delta in sorted(range(-window, window + 1), key=abs):
        attempts += 1
        candidate = NaiveResetService.make_token(email, base + delta)
        if service.redeem(candidate) == email:
            return candidate, attempts
    return None


# --------------------------------------------------------------------------
# Fixed implementation
# --------------------------------------------------------------------------
@dataclass
class _Record:
    user_id: str
    token_hash: bytes
    expires_at: float
    used: bool = False


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


@dataclass
class ResetTokenService:
    now: Callable[[], float]
    ttl_seconds: int = 30 * 60
    token_bytes: int = 32
    _by_hash: Dict[bytes, _Record] = field(default_factory=dict)
    _latest_for_user: Dict[str, bytes] = field(default_factory=dict)

    def request_reset(self, user_id: str) -> str:
        """Create a token, invalidate older ones for this user, return the raw token.

        The raw token only ever exists in the email link; we keep its hash.
        """
        old = self._latest_for_user.pop(user_id, None)
        if old is not None:
            self._by_hash.pop(old, None)
        token = secrets.token_urlsafe(self.token_bytes)
        h = _hash(token)
        self._by_hash[h] = _Record(user_id, h, self.now() + self.ttl_seconds)
        self._latest_for_user[user_id] = h
        return token

    def redeem(self, token: str) -> Optional[str]:
        """Return the user id if ``token`` is valid, and consume it. Else None."""
        if not isinstance(token, str) or not 20 <= len(token) <= 200:
            return None
        h = _hash(token)
        rec = self._by_hash.get(h)
        if rec is None or not hmac.compare_digest(rec.token_hash, h):
            return None
        if rec.used or self.now() >= rec.expires_at:
            self._by_hash.pop(h, None)
            return None
        rec.used = True
        del self._by_hash[h]
        self._latest_for_user.pop(rec.user_id, None)
        return rec.user_id

    def stored_hashes(self) -> list[bytes]:
        """What a database dump would contain."""
        return list(self._by_hash)
