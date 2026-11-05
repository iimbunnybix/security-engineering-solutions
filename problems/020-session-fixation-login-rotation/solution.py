"""Session fixation: rotate the session ID at login and refuse client-chosen IDs.

The original session code kept the same session ID before and after login, and
it also accepted any session ID a browser sent, creating a session under that
ID if none existed. An attacker could therefore plant a known ID in a victim's
browser, wait for the victim to log in, and then use the same ID as the victim.
``SessionManager`` fixes this by only ever issuing server-generated IDs, issuing
a brand-new ID whenever the privilege level changes (login, step-up, logout),
and deleting the old ID so it is worthless.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Callable

SESSION_ID_BYTES = 32
LEVEL_ANONYMOUS = "anonymous"
LEVEL_USER = "user"
LEVEL_STEP_UP = "step_up"     # re-authenticated recently, e.g. for payouts


def random_session_id() -> str:
    """256 random bits, URL-safe, unguessable."""
    return secrets.token_urlsafe(SESSION_ID_BYTES)


@dataclass
class Session:
    user_id: str | None = None
    level: str = LEVEL_ANONYMOUS
    # Non-security data the user expects to keep across login, e.g. a cart.
    data: dict = field(default_factory=dict)


class NaiveSessionManager:
    """The original code: adopts client IDs and never changes the ID."""

    def __init__(self) -> None:
        self.sessions: dict[str, Session] = {}

    def start(self, cookie_session_id: str | None) -> str:
        """Use the browser's ID as-is, creating a session under it if unknown."""
        if cookie_session_id is None:
            cookie_session_id = random_session_id()
        self.sessions.setdefault(cookie_session_id, Session())
        return cookie_session_id

    def login(self, session_id: str, user_id: str) -> str:
        """Mark the existing session as logged in, keeping the same ID."""
        session = self.sessions[session_id]
        session.user_id = user_id
        session.level = LEVEL_USER
        return session_id

    def current_user(self, session_id: str) -> str | None:
        """The logged-in user for this ID, or None if anonymous or unknown."""
        session = self.sessions.get(session_id)
        return session.user_id if session else None


class SessionManager:
    """Server-issued IDs that rotate on every privilege change."""

    def __init__(self, id_factory: Callable[[], str] = random_session_id) -> None:
        self.sessions: dict[str, Session] = {}
        self.id_factory = id_factory

    def start(self, cookie_session_id: str | None) -> str:
        """Return the browser's ID only if we issued it; otherwise issue a new one.

        Refusing unknown IDs ("strict mode") stops an attacker from choosing
        the ID in advance and planting it in the victim's browser.
        """
        if cookie_session_id is not None and cookie_session_id in self.sessions:
            return cookie_session_id
        return self._issue(Session())

    def login(self, session_id: str, user_id: str) -> str:
        """Move the session to a fresh ID at login and destroy the old one."""
        old_session = self._require(session_id)
        new_session = Session(user_id=user_id, level=LEVEL_USER, data=dict(old_session.data))
        return self._rotate(session_id, new_session)

    def step_up(self, session_id: str) -> str:
        """After re-authentication (e.g. MFA), raise the level under a new ID."""
        old_session = self._require(session_id)
        if old_session.user_id is None:
            raise PermissionError("must be logged in to step up")
        new_session = Session(old_session.user_id, LEVEL_STEP_UP, dict(old_session.data))
        return self._rotate(session_id, new_session)

    def logout(self, session_id: str) -> str:
        """Destroy the session entirely and hand back a new anonymous one.

        Shopping data is dropped on purpose: after logout the next person at
        a shared computer must not see the previous user's cart.
        """
        self.sessions.pop(session_id, None)
        return self._issue(Session())

    def current_user(self, session_id: str) -> str | None:
        """The logged-in user for this ID, or None if anonymous or unknown."""
        session = self.sessions.get(session_id)
        return session.user_id if session else None

    def level(self, session_id: str) -> str:
        """Privilege level for this ID; unknown IDs count as anonymous."""
        session = self.sessions.get(session_id)
        return session.level if session else LEVEL_ANONYMOUS

    def _require(self, session_id: str) -> Session:
        """Look up a session we issued, refusing IDs we never handed out."""
        session = self.sessions.get(session_id)
        if session is None:
            raise KeyError("unknown session")
        return session

    def _rotate(self, old_session_id: str, new_session: Session) -> str:
        """Store the new session first, then delete the old ID so it stops working."""
        new_session_id = self._issue(new_session)
        del self.sessions[old_session_id]
        return new_session_id

    def _issue(self, session: Session) -> str:
        """Store a session under a fresh, never-used ID."""
        session_id = self.id_factory()
        # A collision is practically impossible with 256 bits, but a reused
        # ID would hand one user's session to another, so check anyway.
        while session_id in self.sessions:
            session_id = self.id_factory()
        self.sessions[session_id] = session
        return session_id
