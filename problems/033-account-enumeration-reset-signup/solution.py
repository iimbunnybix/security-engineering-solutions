"""Forgot-password and signup endpoints that do not reveal which emails have accounts.

The original endpoints answered "No account found for that email" or "An
account with this email already exists", and only did the slow work (sending
an email over SMTP, hashing a password) for one of the two cases. Both the
message and the response time told anyone whether an address was registered,
so a script could check a leaked email list against the site.

The fix gives one response per endpoint whatever the account state, does the
same work on both branches (always hash the submitted password, always enqueue
exactly one email), and moves email delivery off the request path into an
outbox that a background worker drains.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Callable, Protocol

MAX_EMAIL_LENGTH = 254                 # RFC 5321 path limit
MIN_PASSWORD_LENGTH = 12
RESET_TOKEN_BYTES = 32

GENERIC_RESET_REPLY = "If an account exists for that address, we have emailed a reset link."
GENERIC_SIGNUP_REPLY = "Check your inbox to finish creating your account."
INVALID_EMAIL_REPLY = "Enter a valid email address."
WEAK_PASSWORD_REPLY = f"Use a password of at least {MIN_PASSWORD_LENGTH} characters."

Response = tuple[int, str]
TokenFactory = Callable[[], str]


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str:
        """Return a slow, salted hash of ``password``."""


class Mailer(Protocol):
    def send(self, to: str, template: str, data: dict[str, str]) -> None:
        """Deliver one email (slow: talks to an SMTP server)."""


@dataclass
class Account:
    email: str
    password_hash: str
    verified: bool = False


def new_token() -> str:
    """A 256-bit URL-safe token from the OS CSPRNG."""
    return secrets.token_urlsafe(RESET_TOKEN_BYTES)


def token_digest(token: str) -> str:
    """Store only a hash of tokens, so a database leak does not leak usable links."""
    return hashlib.sha256(token.encode()).hexdigest()


# --- original version ---------------------------------------------------
class NaiveAccountEndpoints:
    """The bug: replies and timing differ depending on whether the email is registered."""

    def __init__(self, users: dict[str, Account], hasher: PasswordHasher, mailer: Mailer) -> None:
        self.users = users
        self.hasher = hasher
        self.mailer = mailer

    def forgot_password(self, raw_email: str) -> Response:
        """Unknown email: fast 404. Known email: SMTP send inside the request, then 200."""
        email = raw_email.strip().lower()
        if email not in self.users:
            return 404, "No account found for that email address."
        self.mailer.send(email, "password_reset", {"token": new_token()})
        return 200, f"We have sent a reset link to {email}."

    def signup(self, raw_email: str, password: str) -> Response:
        """Existing email: fast 409. New email: hash + SMTP send, then 201."""
        email = raw_email.strip().lower()
        if email in self.users:
            return 409, "An account with this email already exists. Log in instead."
        self.users[email] = Account(email, self.hasher.hash(password))
        self.mailer.send(email, "verify_email", {"token": new_token()})
        return 201, "Account created. Check your inbox to verify your email."


# --- fixed version ------------------------------------------------------
@dataclass
class OutboxEmail:
    to: str
    template: str
    data: dict[str, str]


@dataclass
class EmailOutbox:
    """Emails queued by request handlers and delivered later by a worker."""

    pending: list[OutboxEmail] = field(default_factory=list)

    def enqueue(self, to: str, template: str, data: dict[str, str]) -> None:
        """Cheap and constant-cost: in production this is one INSERT in the request's transaction."""
        self.pending.append(OutboxEmail(to, template, data))

    def deliver_all(self, mailer: Mailer) -> int:
        """Background worker step: send everything queued so far. Returns how many were sent."""
        sent = 0
        while self.pending:
            email = self.pending.pop(0)
            mailer.send(email.to, email.template, email.data)
            sent += 1
        return sent


def normalize_email(raw_email: str) -> str | None:
    """Trim and lowercase, then apply a basic shape check. Returns None if invalid.

    Validation depends only on the input, never on whether an account exists,
    so a 400 does not leak anything either.
    """
    email = raw_email.strip().lower()
    if not email or len(email) > MAX_EMAIL_LENGTH:
        return None
    if email.count("@") != 1 or any(ch.isspace() for ch in email):
        return None
    local, domain = email.split("@")
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        return None
    return email


class AccountEndpoints:
    """Same status, same body and the same work for registered and unregistered emails."""

    def __init__(self, users: dict[str, Account], hasher: PasswordHasher, outbox: EmailOutbox,
                 make_token: TokenFactory = new_token) -> None:
        self.users = users
        self.hasher = hasher
        self.outbox = outbox
        self.make_token = make_token
        self.reset_tokens: dict[str, str] = {}          # token digest -> email
        self.verify_tokens: dict[str, str] = {}         # token digest -> email

    def forgot_password(self, raw_email: str) -> Response:
        """Always 202 with the same text; exactly one email is queued either way."""
        email = normalize_email(raw_email)
        if email is None:
            return 400, INVALID_EMAIL_REPLY
        # Generate a token on both branches so the work done is identical.
        token = self.make_token()
        if email in self.users:
            self.reset_tokens[token_digest(token)] = email
            self.outbox.enqueue(email, "password_reset", {"token": token})
        else:
            # Tells a real person who forgot which address they used; tells an
            # attacker nothing, because it goes to the mailbox, not the response.
            self.outbox.enqueue(email, "reset_no_account", {})
        return 202, GENERIC_RESET_REPLY

    def signup(self, raw_email: str, password: str) -> Response:
        """Always 202 with the same text; the password is hashed on both branches."""
        email = normalize_email(raw_email)
        if email is None:
            return 400, INVALID_EMAIL_REPLY
        if len(password) < MIN_PASSWORD_LENGTH:
            return 400, WEAK_PASSWORD_REPLY
        # Hash before looking the email up: the slow step must not depend on
        # whether the account exists. For existing accounts the hash is discarded.
        password_hash = self.hasher.hash(password)
        token = self.make_token()
        if email in self.users:
            # Never touch the existing account (no password overwrite); tell its owner instead.
            self.outbox.enqueue(email, "signup_existing_account", {})
        else:
            self.users[email] = Account(email, password_hash)
            self.verify_tokens[token_digest(token)] = email
            self.outbox.enqueue(email, "verify_email", {"token": token})
        return 202, GENERIC_SIGNUP_REPLY

    def email_for_reset_token(self, token: str) -> str | None:
        """Look up which account a reset link belongs to (None if unknown)."""
        return self.reset_tokens.get(token_digest(token))
