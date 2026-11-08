"""Step-up re-authentication before password, email and MFA changes.

The original account settings trusted any valid session cookie: whoever held
it could set a new password, a new email and switch off two-factor login
without knowing the current password. A cookie left on a shared computer was
enough to lock the real owner out for good.

The fix records ``auth_time`` (when the user last proved who they are) in the
session, separately from ordinary activity. Sensitive actions need either the
current password in the same request or an ``auth_time`` within the last
five minutes. Repeated wrong passwords end the session, so a cookie thief
cannot guess the password through the settings page. Time comes from an
injectable clock so tests can move it.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Protocol

REAUTH_WINDOW_SECONDS = 5 * 60
MAX_REAUTH_FAILURES = 5
PBKDF2_ITERATIONS = 100_000
SALT_BYTES = 16


class Clock(Protocol):
    def now(self) -> float: ...


class StepUpRequired(PermissionError):
    """The session is valid but has not proved the password recently."""


class SessionRevoked(PermissionError):
    """The session was ended (for example after too many wrong passwords)."""


def hash_password(password: str, salt: bytes | None = None) -> bytes:
    """Salted PBKDF2-SHA256; returns salt + digest."""
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return salt + digest


def password_matches(password: str, stored: bytes) -> bool:
    """Recompute with the stored salt and compare in constant time."""
    salt = stored[:SALT_BYTES]
    return hmac.compare_digest(hash_password(password, salt), stored)


@dataclass
class Account:
    user_id: int
    email: str
    password_hash: bytes
    mfa_enabled: bool = True


@dataclass
class Session:
    session_id: str
    user_id: int
    auth_time: float        # last time the password was proved
    last_seen: float        # last request of any kind; NOT proof of identity
    reauth_failures: int = 0
    revoked: bool = False


def log_in(account: Account, password: str, clock: Clock) -> Session | None:
    """Full login: a correct password starts a session with a fresh auth_time."""
    if not password_matches(password, account.password_hash):
        return None
    now = clock.now()
    return Session(secrets.token_urlsafe(32), account.user_id, auth_time=now, last_seen=now)


def touch(session: Session, clock: Clock) -> None:
    """Ordinary request: keeps the session alive but does not refresh auth_time."""
    session.last_seen = clock.now()


# ---------------------------------------------------------------- original
def naive_change_password(session: Session, account: Account, new_password: str) -> None:
    """ORIGINAL: a valid session cookie is all it takes."""
    account.password_hash = hash_password(new_password)


def naive_change_email(session: Session, account: Account, new_email: str) -> None:
    """ORIGINAL: no check beyond the session either."""
    account.email = new_email


# --------------------------------------------------------------------- fix
def is_recently_authenticated(session: Session, clock: Clock) -> bool:
    """True when the password was proved within the window (and not in the future)."""
    age = clock.now() - session.auth_time
    # A negative age means a clock jump or a forged value; do not trust it.
    return 0 <= age <= REAUTH_WINDOW_SECONDS


def _record_failure(session: Session) -> None:
    """Count a wrong password; end the session once the limit is reached."""
    session.reauth_failures += 1
    if session.reauth_failures >= MAX_REAUTH_FAILURES:
        session.revoked = True


def require_step_up(session: Session, account: Account,
                    current_password: str | None, clock: Clock) -> None:
    """Gate for sensitive actions. Raises unless identity was proved recently.

    Supplying the current password proves identity right now and refreshes
    auth_time; otherwise a login or re-auth inside the window is required.
    """
    if session.revoked:
        raise SessionRevoked("session has ended")
    if session.user_id != account.user_id:
        raise PermissionError("session belongs to another account")
    if current_password is not None:
        if not password_matches(current_password, account.password_hash):
            _record_failure(session)
            raise StepUpRequired("current password is wrong")
        session.auth_time = clock.now()
        session.reauth_failures = 0
        return
    if not is_recently_authenticated(session, clock):
        raise StepUpRequired("please enter your password again")


def reauthenticate(session: Session, account: Account, password: str, clock: Clock) -> None:
    """The "confirm your password" prompt: unlocks sensitive actions for a while."""
    require_step_up(session, account, password, clock)


def change_password(session: Session, account: Account, new_password: str,
                    clock: Clock, current_password: str | None = None) -> None:
    """FIX: change the password only after step-up."""
    require_step_up(session, account, current_password, clock)
    account.password_hash = hash_password(new_password)


def change_email(session: Session, account: Account, new_email: str,
                 clock: Clock, current_password: str | None = None) -> None:
    """FIX: change the login email only after step-up."""
    require_step_up(session, account, current_password, clock)
    account.email = new_email


def disable_mfa(session: Session, account: Account, clock: Clock,
                current_password: str | None = None) -> None:
    """FIX: switching off two-factor login also needs step-up."""
    require_step_up(session, account, current_password, clock)
    account.mfa_enabled = False
