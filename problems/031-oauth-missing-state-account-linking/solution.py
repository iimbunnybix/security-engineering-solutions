"""OAuth "Connect your Google account" flow without a `state` check.

The original callback took the authorization `code` from the URL and linked
whatever provider identity it belonged to onto the account of whoever was
logged in. An attacker started the flow with their OWN provider account,
stopped before the callback, and tricked a logged-in victim into opening
the callback URL. The attacker's identity got linked to the victim's
account, so "Sign in with Google" then logged the attacker in as the victim.

The fix binds every flow to the browser session that started it: a random,
single-use, short-lived `state` is stored in the session and must come back
unchanged on the callback before the code is ever exchanged.
"""
from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass, field

STATE_BYTES = 32                 # 256 bits: cannot be guessed
STATE_LIFETIME_SECONDS = 600     # a real user finishes the consent screen in minutes


class OAuthError(Exception):
    """Raised when a callback must be refused."""


@dataclass
class Session:
    """Server-side session for one browser."""
    user_id: str | None
    # state value -> time it expires; held server-side, never trusted from the URL
    pending_oauth_states: dict[str, float] = field(default_factory=dict)


class FakeIdentityProvider:
    """Stands in for Google/GitHub: hands out one-time codes for an identity."""

    def __init__(self) -> None:
        self._codes: dict[str, str] = {}

    def authorize(self, provider_user_id: str) -> str:
        """User approved the consent screen; return the code put in the callback URL."""
        code = secrets.token_urlsafe(16)
        self._codes[code] = provider_user_id
        return code

    def exchange(self, code: str) -> str:
        """Trade a code for the identity it belongs to. Codes work once."""
        if code not in self._codes:
            raise OAuthError("invalid or already used code")
        return self._codes.pop(code)

    def has_unused_code(self, code: str) -> bool:
        """Test helper: was this code left unexchanged?"""
        return code in self._codes


class AccountStore:
    """Which provider identity is linked to which local account."""

    def __init__(self, provider: FakeIdentityProvider) -> None:
        self.provider = provider
        self.linked: dict[str, str] = {}   # provider_user_id -> local user_id

    def link(self, provider_user_id: str, user_id: str) -> None:
        """Remember that this provider identity may sign in as user_id."""
        self.linked[provider_user_id] = user_id

    def sign_in_with_provider(self, code: str) -> str:
        """'Sign in with Google': return the local account for the code's identity."""
        provider_user_id = self.provider.exchange(code)
        if provider_user_id not in self.linked:
            raise OAuthError("no account linked to this identity")
        return self.linked[provider_user_id]


def original_link_callback(store: AccountStore, session: Session, code: str) -> None:
    """VULNERABLE: links the code's identity to whoever is logged in.

    Nothing ties the code to the browser that started the flow, so a code
    obtained by the attacker can be 'finished' in the victim's browser.
    """
    if session.user_id is None:
        raise OAuthError("not logged in")
    provider_user_id = store.provider.exchange(code)
    store.link(provider_user_id, session.user_id)


def start_link_flow(session: Session, now: float) -> str:
    """Begin a link flow and return the `state` to put in the authorize URL."""
    if session.user_id is None:
        raise OAuthError("not logged in")
    _drop_expired_states(session, now)
    state = secrets.token_urlsafe(STATE_BYTES)
    session.pending_oauth_states[state] = now + STATE_LIFETIME_SECONDS
    return state


def _drop_expired_states(session: Session, now: float) -> None:
    """Forget abandoned flows so the session does not grow forever."""
    for state, expires_at in list(session.pending_oauth_states.items()):
        if expires_at <= now:
            del session.pending_oauth_states[state]


def _consume_state(session: Session, returned_state: str | None, now: float) -> None:
    """Accept the callback's state only if THIS session issued it recently.

    The matching entry is removed first, so a state can never be used twice.
    """
    if not returned_state:
        raise OAuthError("missing state")
    matched_state = None
    for issued_state in session.pending_oauth_states:
        # Constant-time compare so timing does not reveal a valid state.
        if hmac.compare_digest(issued_state.encode(), returned_state.encode()):
            matched_state = issued_state
    if matched_state is None:
        raise OAuthError("state does not belong to this session")
    expires_at = session.pending_oauth_states.pop(matched_state)
    if expires_at <= now:
        raise OAuthError("state expired")


def safe_link_callback(store: AccountStore, session: Session, code: str,
                       returned_state: str | None, now: float) -> None:
    """FIXED: check the state BEFORE exchanging the code, then link."""
    if session.user_id is None:
        raise OAuthError("not logged in")
    # Validate first: an attacker's code must never be exchanged in our name.
    _consume_state(session, returned_state, now)
    provider_user_id = store.provider.exchange(code)
    already_linked_to = store.linked.get(provider_user_id)
    # One identity signs in to one account; silently moving it is a takeover too.
    if already_linked_to is not None and already_linked_to != session.user_id:
        raise OAuthError("identity already linked to a different account")
    store.link(provider_user_id, session.user_id)
