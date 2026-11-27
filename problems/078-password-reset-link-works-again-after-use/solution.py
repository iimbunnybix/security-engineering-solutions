"""A password reset link kept working after it had been used.

Reset tokens were random and expired after one hour, but they were not
single-use: after the owner set a new password, the same link still worked
until the hour was up. Anyone who later saw the URL (browser history on a
shared computer, a forwarded email, proxy logs) could set the password again.

The fix stores only a SHA-256 hash of each token, claims the token with an
atomic compare-and-set on first use (so two simultaneous submissions cannot
both win), invalidates every other outstanding reset token of that user
whenever the password changes, and keeps the one-hour expiry.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass

TOKEN_LIFETIME_SECONDS = 60 * 60
TOKEN_BYTES = 32
MIN_PASSWORD_LENGTH = 8
# Low on purpose so the tests run fast; production needs 600,000+ (OWASP).
DEMO_PBKDF2_ITERATIONS = 1_000
SALT_BYTES = 16


class InvalidResetToken(ValueError):
    """The link is unknown, expired or already used (HTTP 400)."""


class FakeClock:
    """A clock the tests move by hand, so expiry checks are deterministic."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def time(self) -> float:
        """Current fake time in seconds."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Move time forward."""
        self.now += seconds


def hash_password(password: str, salt: bytes) -> bytes:
    """Salted PBKDF2 hash of a password."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, DEMO_PBKDF2_ITERATIONS)


class UserStore:
    """Users and their password hashes, shared by both reset services."""

    def __init__(self) -> None:
        self._passwords: dict[str, tuple[bytes, bytes]] = {}

    def set_password(self, email: str, password: str) -> None:
        """Store a fresh salt and hash for the user."""
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError("password too short")
        salt = secrets.token_bytes(SALT_BYTES)
        self._passwords[email] = (salt, hash_password(password, salt))

    def check_password(self, email: str, password: str) -> bool:
        """True if the password matches, compared in constant time."""
        if email not in self._passwords:
            return False
        salt, stored = self._passwords[email]
        return hmac.compare_digest(stored, hash_password(password, salt))


# ---------------------------------------------------------------- original
class OriginalResetService:
    """Legacy reset: random, expiring tokens that are never used up."""

    def __init__(self, users: UserStore, clock: FakeClock) -> None:
        self.users = users
        self.clock = clock
        self._tokens: dict[str, tuple[str, float]] = {}  # raw token -> (email, expiry)

    def request_reset(self, email: str) -> str:
        """Create a token and return it (the real app emails a link)."""
        token = secrets.token_urlsafe(TOKEN_BYTES)
        self._tokens[token] = (email, self.clock.time() + TOKEN_LIFETIME_SECONDS)
        return token

    def reset_password(self, token: str, new_password: str) -> None:
        """Set a new password. BUG: the token is left valid afterwards."""
        if token not in self._tokens:
            raise InvalidResetToken("unknown token")
        email, expires_at = self._tokens[token]
        if self.clock.time() >= expires_at:
            raise InvalidResetToken("expired")
        self.users.set_password(email, new_password)


# ---------------------------------------------------------------- the fix
def hash_token(token: str) -> str:
    """SHA-256 of the token. A leaked table of these cannot be used as links."""
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class ResetRecord:
    """One reset link as stored on the server (never the raw token)."""

    email: str
    expires_at: float
    used: bool = False


class ResetService:
    """Reset tokens that are hashed at rest, single-use and expiring."""

    def __init__(self, users: UserStore, clock: FakeClock) -> None:
        self.users = users
        self.clock = clock
        self._records: dict[str, ResetRecord] = {}  # token hash -> record
        # WHY a lock: "check unused, then mark used" must be one step,
        # like UPDATE ... SET used=1 WHERE hash=? AND used=0 in a database.
        self._lock = threading.Lock()

    def request_reset(self, email: str) -> str:
        """Create a token, keep only its hash, return the raw token once."""
        token = secrets.token_urlsafe(TOKEN_BYTES)
        expires_at = self.clock.time() + TOKEN_LIFETIME_SECONDS
        with self._lock:
            self._records[hash_token(token)] = ResetRecord(email, expires_at)
        return token

    def claim_token(self, token: str) -> str:
        """Atomically mark the token used and return its email, or raise.

        Compare-and-set: of two simultaneous calls with the same token,
        exactly one sees used=False and flips it; the other is refused.
        """
        with self._lock:
            record = self._records.get(hash_token(token))
            if record is None or record.used:
                raise InvalidResetToken("unknown or already used")
            if self.clock.time() >= record.expires_at:
                raise InvalidResetToken("expired")
            record.used = True
            return record.email

    def reset_password(self, token: str, new_password: str) -> None:
        """Use the link once to set a new password."""
        # Validate first so a too-short password does not burn the link.
        if len(new_password) < MIN_PASSWORD_LENGTH:
            raise ValueError("password too short")
        email = self.claim_token(token)
        self.users.set_password(email, new_password)
        self.invalidate_all_tokens_for(email)

    def change_password(self, email: str, old_password: str, new_password: str) -> None:
        """Logged-in password change; it also kills outstanding reset links."""
        if not self.users.check_password(email, old_password):
            raise PermissionError("wrong current password")
        self.users.set_password(email, new_password)
        self.invalidate_all_tokens_for(email)

    def invalidate_all_tokens_for(self, email: str) -> None:
        """Mark every reset token of this user used.

        WHY: an older link from a second "forgot password" click must not
        undo the password the user just chose.
        """
        with self._lock:
            for record in self._records.values():
                if record.email == email:
                    record.used = True

    def stored_token_hashes(self) -> list[str]:
        """What a database dump would reveal (for tests)."""
        with self._lock:
            return list(self._records)
