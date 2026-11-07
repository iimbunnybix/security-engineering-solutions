"""Bind "email verified" to the exact address that was verified.

The team-chat app auto-joins users to a company workspace when their
*verified* email is on the company's domain. Verification was stored as a
boolean ``email_verified`` on the account, and changing the email address
did not reset it. An attacker verified his own mailbox, changed the address
to ``someone@victim-corp.test`` and was auto-joined to that company.

The fix stores WHICH address was verified. A new address waits in
``pending_email`` until a single-use token sent to that address is
confirmed; until then the old address stays in force, and "verified" means
"the current address equals the verified address".
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

TOKEN_BYTES = 32
TOKEN_LIFETIME_SECONDS = 24 * 60 * 60


class VerificationError(ValueError):
    """Token unknown, expired, already used or for a different address."""


def normalise_email(address: str) -> str:
    """Lower-case and trim so ``Asha@X.test`` and ``asha@x.test`` match."""
    return address.strip().lower()


def email_domain(address: str) -> str:
    """Return the part after the last ``@``."""
    return normalise_email(address).rpartition("@")[2]


@dataclass
class Account:
    user_id: int
    email: str
    # Original model: one boolean that is not tied to any address.
    email_verified: bool = False
    # Fixed model: the exact address that was proven, and a pending change.
    verified_email: str | None = None
    pending_email: str | None = None


@dataclass
class Workspace:
    """A company workspace that auto-joins verified users on its domain."""
    domain: str
    members: set[int] = field(default_factory=set)


# ---------------------------------------------------------------- original
def naive_change_email(account: Account, new_email: str) -> None:
    """Original code: swaps the address, keeps the old verified flag."""
    account.email = normalise_email(new_email)


def naive_auto_join(account: Account, workspace: Workspace) -> bool:
    """Original code: trusts the boolean for whatever address is there now."""
    if account.email_verified and email_domain(account.email) == workspace.domain:
        workspace.members.add(account.user_id)
        return True
    return False


# --------------------------------------------------------------------- fix
def is_verified(account: Account) -> bool:
    """Verified means the CURRENT address is the one that was proven."""
    if account.verified_email is None:
        return False
    return account.verified_email == normalise_email(account.email)


@dataclass
class PendingToken:
    user_id: int
    email: str
    expires_at: float


class EmailVerifier:
    """Issues and redeems single-use tokens tied to (user, address)."""

    def __init__(self) -> None:
        # Store only a hash of each token, so a database leak gives nothing usable.
        self._tokens: dict[str, PendingToken] = {}

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue(self, account: Account, address: str, now: float) -> str:
        """Create a token for ``address``; the caller emails it to that address."""
        token = secrets.token_urlsafe(TOKEN_BYTES)
        pending = PendingToken(account.user_id, normalise_email(address),
                               now + TOKEN_LIFETIME_SECONDS)
        self._tokens[self._hash(token)] = pending
        return token

    def redeem(self, account: Account, token: str, now: float) -> str:
        """Return the address the token proves, or raise ``VerificationError``."""
        # pop() makes the token single-use even if the checks below fail.
        pending = self._tokens.pop(self._hash(token), None)
        if pending is None:
            raise VerificationError("unknown or already used token")
        if pending.user_id != account.user_id:
            raise VerificationError("token belongs to another account")
        if now >= pending.expires_at:
            raise VerificationError("token expired")
        return pending.email


def request_email_change(account: Account, new_email: str,
                         verifier: EmailVerifier, now: float) -> str:
    """Start a change: the new address is pending, the old one stays active."""
    account.pending_email = normalise_email(new_email)
    return verifier.issue(account, account.pending_email, now)


def confirm_email(account: Account, token: str, verifier: EmailVerifier, now: float) -> None:
    """Finish a change (or first verification) with a token from the inbox."""
    proven = verifier.redeem(account, token, now)
    current = normalise_email(account.email)
    # The token must prove the address the user is switching to (or the
    # current one for first-time verification), not some earlier request.
    if proven == account.pending_email:
        account.email = proven
        account.pending_email = None
    elif proven != current:
        raise VerificationError("token is for an address no longer requested")
    account.verified_email = proven


def auto_join(account: Account, workspace: Workspace) -> bool:
    """Join only if the current address is verified and on the domain."""
    if is_verified(account) and email_domain(account.email) == workspace.domain:
        workspace.members.add(account.user_id)
        return True
    return False
