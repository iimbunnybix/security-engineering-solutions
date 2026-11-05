"""Revoke existing sessions when a user resets their password.

The original bug: the web app stored sessions server-side, but changing or
resetting a password only updated the password hash. Every session that was
already logged in, including ones on a lost laptop or a shared computer, kept
working until it expired 30 days later. Users who reset their password
"to log everyone else out" were not protected at all.

Fix:
* Each user has a ``session_epoch``. A session records the epoch it was
  created in and is valid only while that still matches the user's epoch.
* A password change/reset, "log out everywhere", or an admin lock bumps the
  epoch, invalidating every existing session in O(1) without scanning them.
  The session that made the change is re-issued so the user stays signed in.
* Sessions also have an idle timeout and an absolute lifetime.
* Tokens are random and only their SHA-256 hash is stored, so a leaked
  session table cannot be replayed as cookies.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

MIN_PASSWORD_LENGTH = 12


class FakeClock:
    def __init__(self, t: float = 0.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class _Session:
    user: str
    epoch: int
    created: float
    last_seen: float


@dataclass
class _User:
    password_hash: str
    session_epoch: int = 0


def _hash_password(pw: str, salt: bytes) -> str:
    return salt.hex() + ":" + hashlib.scrypt(pw.encode(), salt=salt, n=2**12, r=8, p=1).hex()


def _check_password(pw: str, stored: str) -> bool:
    salt_hex, _ = stored.split(":", 1)
    return secrets.compare_digest(_hash_password(pw, bytes.fromhex(salt_hex)), stored)


def _validate_new_password(new: str) -> None:
    """One password policy for every path that sets a password."""
    if len(new) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")


@dataclass
class AuthService:
    clock: FakeClock
    idle_timeout: float = 30 * 60
    absolute_lifetime: float = 12 * 3600
    revoke_on_password_change: bool = True      # False reproduces the original bug
    users: dict[str, _User] = field(default_factory=dict)
    sessions: dict[str, _Session] = field(default_factory=dict)   # sha256(token) -> session

    def register(self, user: str, password: str) -> None:
        """Create a new account. Refuses an existing username.

        Overwriting would restart ``session_epoch`` at 0 and bring revoked
        epoch-0 sessions back to life for whoever owns the new account.
        """
        if user in self.users:
            raise ValueError("username already registered")
        self.users[user] = _User(_hash_password(password, secrets.token_bytes(16)))

    def login(self, user: str, password: str) -> str | None:
        u = self.users.get(user)
        if u is None or not _check_password(password, u.password_hash):
            return None
        return self._issue(user)

    def _issue(self, user: str) -> str:
        token = secrets.token_urlsafe(32)
        now = self.clock.now()
        self.sessions[_digest(token)] = _Session(user, self.users[user].session_epoch, now, now)
        return token

    def authenticate(self, token: str | None) -> str | None:
        """Return the user for a valid session cookie, else None (and forget dead sessions)."""
        if not token:
            return None
        key = _digest(token)
        s = self.sessions.get(key)
        if s is None:
            return None
        now = self.clock.now()
        u = self.users.get(s.user)
        expired = now - s.last_seen > self.idle_timeout or now - s.created > self.absolute_lifetime
        revoked = u is None or s.epoch != u.session_epoch
        if expired or revoked:
            del self.sessions[key]
            return None
        s.last_seen = now
        return s.user

    def change_password(self, token: str, old: str, new: str) -> str:
        """Change password from an authenticated session.

        Returns the session token the caller should now use (a fresh one when
        revocation is on, because all old ones, including the current, are dead).
        """
        user = self.authenticate(token)
        if user is None:
            raise PermissionError("not authenticated")
        u = self.users[user]
        if not _check_password(old, u.password_hash):
            raise PermissionError("current password is wrong")
        _validate_new_password(new)
        u.password_hash = _hash_password(new, secrets.token_bytes(16))
        if not self.revoke_on_password_change:
            return token
        self.revoke_all(user)
        return self._issue(user)

    def reset_password(self, user: str, new: str) -> None:
        """Called after the emailed reset link is verified. Signs out everywhere."""
        # Same policy as change_password, checked before anything changes, so
        # "forgot password" is not a way around the length rule.
        _validate_new_password(new)
        u = self.users[user]
        u.password_hash = _hash_password(new, secrets.token_bytes(16))
        if self.revoke_on_password_change:
            self.revoke_all(user)

    def revoke_all(self, user: str) -> None:
        """'Log out of all devices': O(1), old sessions fail on their next request."""
        self.users[user].session_epoch += 1

    def logout(self, token: str) -> None:
        self.sessions.pop(_digest(token), None)

    def active_sessions(self, user: str) -> int:
        u = self.users[user]
        return sum(1 for s in self.sessions.values() if s.user == user and s.epoch == u.session_epoch)
