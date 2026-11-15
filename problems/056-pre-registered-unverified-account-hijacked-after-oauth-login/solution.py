"""Account linking that does not hand pre-registered accounts to attackers.

An attacker signs up with the victim's email and a password of their own but
never verifies the email. Later the victim clicks "Sign in with Google"; the
app finds an account with that email and links the Google identity to it.
The victim now works in an account whose password the attacker set, and the
attacker's open session keeps working ("pre-account hijacking"). This module
links by email only when the provider vouches for that email, and when the
existing account was never verified it deletes the unproven password and
revokes every session before linking.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field

# Kept low so the tests run fast; production PBKDF2-HMAC-SHA256 should use
# OWASP's current recommendation (600,000 iterations) or a memory-hard hash.
PBKDF2_ITERATIONS = 100_000
SALT_BYTES = 16
SESSION_TOKEN_BYTES = 32


class LinkRefused(Exception):
    """The OAuth identity cannot be safely attached to an existing account."""


@dataclass(frozen=True)
class OAuthIdentity:
    """What the identity provider tells us after a successful sign-in."""
    provider: str
    subject: str           # the provider's stable user id ("sub" claim)
    email: str
    email_verified: bool   # the provider's "email_verified" claim


@dataclass
class Account:
    email: str
    password_salt: bytes | None = None
    password_hash: bytes | None = None
    email_verified: bool = False
    # (provider, subject) pairs that may sign in to this account.
    linked_identities: set[tuple[str, str]] = field(default_factory=set)


def hash_password(password: str, salt: bytes) -> bytes:
    """Slow salted hash so a stolen database does not reveal passwords."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)


class AccountStore:
    """In-memory accounts and sessions (stands in for the user database)."""

    def __init__(self) -> None:
        self.accounts: dict[str, Account] = {}
        self.sessions: dict[str, str] = {}  # session token -> account email

    def signup_with_password(self, email: str, password: str) -> str:
        """Create an unverified password account and log it in."""
        if email.lower() in self.accounts:
            raise ValueError("an account with this email already exists")
        salt = secrets.token_bytes(SALT_BYTES)
        account = Account(email=email.lower(), password_salt=salt,
                          password_hash=hash_password(password, salt))
        self.accounts[account.email] = account
        return self.start_session(account)

    def mark_email_verified(self, email: str) -> None:
        """Called when the user clicks the link in the verification email."""
        self.accounts[email.lower()].email_verified = True

    def login_with_password(self, email: str, password: str) -> str | None:
        """Return a new session token, or None if the password is wrong or removed."""
        account = self.accounts.get(email.lower())
        if account is None or account.password_hash is None:
            return None
        candidate = hash_password(password, account.password_salt)
        if not hmac.compare_digest(candidate, account.password_hash):
            return None
        return self.start_session(account)

    def start_session(self, account: Account) -> str:
        token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
        self.sessions[token] = account.email
        return token

    def revoke_all_sessions(self, account: Account) -> None:
        """Log the account out everywhere."""
        for token, owner in list(self.sessions.items()):
            if owner == account.email:
                del self.sessions[token]

    def account_for_session(self, token: str) -> Account | None:
        email = self.sessions.get(token)
        return None if email is None else self.accounts[email]

    def find_by_identity(self, identity: OAuthIdentity) -> Account | None:
        """Look up an account by an identity that was linked earlier."""
        key = (identity.provider, identity.subject)
        for account in self.accounts.values():
            if key in account.linked_identities:
                return account
        return None


def naive_oauth_login(store: AccountStore, identity: OAuthIdentity) -> str:
    """Original code: link to whatever account has the same email. Vulnerable."""
    account = store.accounts.get(identity.email.lower())
    if account is None:
        account = Account(email=identity.email.lower())
        store.accounts[account.email] = account
    account.linked_identities.add((identity.provider, identity.subject))
    return store.start_session(account)


def take_over_unverified_account(store: AccountStore, account: Account) -> None:
    """Strip everything an unverified sign-up may have planted.

    Nobody proved they own this email when the password was set, so the
    password and every session it created could belong to an attacker.
    """
    account.password_salt = None
    account.password_hash = None
    store.revoke_all_sessions(account)


def oauth_login(store: AccountStore, identity: OAuthIdentity) -> str:
    """Fixed sign-in with an identity provider.

    1. An identity linked before signs in directly.
    2. Linking by email requires the provider to say the email is verified;
       otherwise anyone could create a provider account with your address.
    3. An existing but unverified account is cleaned before linking.
    """
    linked_account = store.find_by_identity(identity)
    if linked_account is not None:
        return store.start_session(linked_account)

    if not identity.email_verified:
        raise LinkRefused("provider has not verified this email address")

    account = store.accounts.get(identity.email.lower())
    if account is None:
        account = Account(email=identity.email.lower())
        store.accounts[account.email] = account
    elif not account.email_verified:
        take_over_unverified_account(store, account)

    # The provider has now proven control of the mailbox for us.
    account.email_verified = True
    account.linked_identities.add((identity.provider, identity.subject))
    return store.start_session(account)
