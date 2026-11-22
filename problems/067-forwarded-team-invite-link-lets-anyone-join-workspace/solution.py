"""Bind team invite links to the person who was invited.

A project-management SaaS invited people to a workspace with a link like
``/join?token=...``. The token was a reusable bearer secret: whoever held
the link could join, as many accounts as they liked, until an admin deleted
the invite. Links were forwarded, pasted in public chats and kept in mail
archives, so outsiders joined customer workspaces and read their projects.

The fix: an invite is created for one (normalised) email address, the
server stores only a SHA-256 hash of the token, and accepting it requires a
signed-in account whose *verified* email equals the invited one. Invites are
single use, expire after 7 days and can be revoked.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

INVITE_TOKEN_BYTES = 32
INVITE_TTL_SECONDS = 7 * 24 * 3600


class InviteError(Exception):
    """The invite cannot be accepted; ``reason`` says why (for logs, not users)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class FakeClock:
    now: float = 0.0


@dataclass(frozen=True)
class Account:
    user_id: str
    email: str
    email_verified: bool


def normalise_email(email: str) -> str:
    """Lower-case and trim, so "Asha@Example.com " matches "asha@example.com"."""
    return email.strip().lower()


def hash_token(token: str) -> str:
    """SHA-256 of the token; a leaked invites table then holds no usable links."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# --- original version ---------------------------------------------------
class NaiveInviteService:
    """The bug: the token alone grants membership, for anyone, any number of times."""

    def __init__(self) -> None:
        self.invites: dict[str, str] = {}              # token -> workspace
        self.members: dict[str, set[str]] = {}

    def create_invite(self, workspace: str, invited_email: str) -> str:
        token = secrets.token_urlsafe(INVITE_TOKEN_BYTES)
        self.invites[token] = workspace                 # email is not recorded
        return token

    def accept(self, token: str, account: Account) -> str:
        workspace = self.invites[token]                 # never consumed, never expires
        self.members.setdefault(workspace, set()).add(account.user_id)
        return workspace


# --- fixed version ------------------------------------------------------
@dataclass
class Invite:
    workspace: str
    invited_email: str
    expires_at: float


@dataclass
class InviteService:
    clock: FakeClock
    invites: dict[str, Invite] = field(default_factory=dict)   # token hash -> invite
    members: dict[str, set[str]] = field(default_factory=dict)

    def create_invite(self, workspace: str, invited_email: str) -> str:
        """Return the raw token to email to ``invited_email``; only its hash is kept."""
        token = secrets.token_urlsafe(INVITE_TOKEN_BYTES)
        self.invites[hash_token(token)] = Invite(
            workspace, normalise_email(invited_email), self.clock.now + INVITE_TTL_SECONDS)
        return token

    def revoke(self, token_hash: str) -> None:
        """Admin action: the invite stops working immediately."""
        self.invites.pop(token_hash, None)

    def accept(self, token: str, account: Account) -> str:
        """Add ``account`` to the invite's workspace, or raise InviteError."""
        token_hash = hash_token(token)
        invite = self.invites.get(token_hash)
        if invite is None:
            raise InviteError("unknown, used or revoked invite")
        if self.clock.now >= invite.expires_at:
            del self.invites[token_hash]
            raise InviteError("invite expired")
        self._require_invited_person(invite, account)
        # Single use: consume before granting so the link cannot be replayed.
        del self.invites[token_hash]
        self.members.setdefault(invite.workspace, set()).add(account.user_id)
        return invite.workspace

    def _require_invited_person(self, invite: Invite, account: Account) -> None:
        """Only a verified owner of the invited address may use the link.

        An unverified email proves nothing: anyone can sign up claiming the
        invited address. A wrong-account attempt does not consume the invite,
        so the real invitee (who may have clicked while signed in to another
        account) can still accept it.
        """
        if not account.email_verified:
            raise InviteError("account email is not verified")
        matches = hmac.compare_digest(normalise_email(account.email).encode("utf-8"),
                                      invite.invited_email.encode("utf-8"))
        if not matches:
            raise InviteError("invite was sent to a different email address")
