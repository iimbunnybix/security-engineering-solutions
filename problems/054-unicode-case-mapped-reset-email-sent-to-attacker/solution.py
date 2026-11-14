"""Password reset that always emails the address stored on the account.

The original "forgot password" handler found the account with a
case-insensitive comparison, `typed.upper() == stored.upper()`, and then sent
the reset link to the address the user TYPED. Unicode case mapping is not
one-to-one: the Turkish dotless "ı" upper-cases to "I", and the Kelvin sign
"K" lower-cases to "k". An attacker who owns the lookalike domain gıthub.test
typed "mike@gıthub.test", matched the victim "mike@github.test", and
received the victim's reset link. This version looks the account up by an
exact canonical key and only ever sends mail to the stored address.
"""
from __future__ import annotations

import secrets
import unicodedata
from dataclasses import dataclass, field

RESET_TOKEN_BYTES = 32


@dataclass
class Account:
    user_id: int
    email: str


@dataclass
class Outbox:
    """Fake mail sender that records (recipient, token) pairs instead of sending."""
    sent: list[tuple[str, str]] = field(default_factory=list)

    def send_reset_link(self, recipient: str, token: str) -> None:
        self.sent.append((recipient, token))


def naive_request_reset(accounts: list[Account], typed_email: str, outbox: Outbox) -> None:
    """Original handler: lossy case comparison, then mails the typed address."""
    for account in accounts:
        if account.email.upper() == typed_email.upper():
            token = secrets.token_urlsafe(RESET_TOKEN_BYTES)
            outbox.send_reset_link(typed_email, token)
            return


def email_lookup_key(email: str) -> str:
    """Canonical key for finding an account by email.

    NFKC folds compatibility forms (full-width letters, the Kelvin sign) to
    their plain letters, and casefold() is Unicode's caseless-matching
    mapping. Unlike upper(), casefold() keeps "ı" distinct from "i", so a
    lookalike domain does not collide with the real one.
    """
    normalised = unicodedata.normalize("NFKC", email.strip())
    return unicodedata.normalize("NFKC", normalised.casefold())


def build_email_index(accounts: list[Account]) -> dict[str, Account]:
    """Map each canonical key to its account, refusing ambiguous data.

    Two stored accounts sharing a key would make every lookup a guess, so we
    fail loudly at index time instead of picking one.
    """
    index: dict[str, Account] = {}
    for account in accounts:
        key = email_lookup_key(account.email)
        if key in index:
            raise ValueError(f"accounts {index[key].user_id} and {account.user_id} share an email key")
        index[key] = account
    return index


def request_reset(email_index: dict[str, Account], typed_email: str, outbox: Outbox) -> None:
    """Send a reset link for the matching account, to the STORED address only.

    The typed address is used solely to find the account. Even if the lookup
    rule ever matches something surprising, the link still goes to the
    mailbox the account owner proved they control at sign-up. Unknown emails
    do nothing, so the response cannot be used to enumerate accounts.
    """
    account = email_index.get(email_lookup_key(typed_email))
    if account is None:
        return
    token = secrets.token_urlsafe(RESET_TOKEN_BYTES)
    outbox.send_reset_link(account.email, token)
