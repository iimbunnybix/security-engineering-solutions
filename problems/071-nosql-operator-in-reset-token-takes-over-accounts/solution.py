"""Stop a JSON query operator in the reset token from resetting anyone's password.

The password-reset endpoint took the JSON body and put the ``email`` and
``token`` values straight into a document-store query. JSON can carry an
object where a string is expected, so a token of ``{"$ne": null}`` became a
query *operator* ("token is not null") that matches every pending reset, and
an attacker reset other people's passwords without ever seeing their email.

The fix validates the body first (exact fields, every value a plain string),
looks the account up by email only, and compares the token in code with a
constant-time check, plus an expiry. Untrusted input never becomes query syntax.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from typing import Callable

Clock = Callable[[], float]

RESET_TOKEN_TTL_S = 30 * 60
TOKEN_BYTES = 32
MAX_FIELD_LENGTH = 256
RESET_FIELDS = frozenset({"email", "token", "new_password"})
MIN_PASSWORD_LENGTH = 12


class BadRequest(Exception):
    """The request body does not have the expected shape (HTTP 400)."""


class ResetRefused(Exception):
    """Unknown email, wrong or expired token (HTTP 400, one generic message)."""


# --- a tiny Mongo-style document store --------------------------------------
def _matches_condition(value: object, condition: object) -> bool:
    """Match one field. A dict condition is read as operators, like MongoDB does."""
    if not isinstance(condition, dict):
        return value == condition
    for operator, operand in condition.items():
        if operator == "$ne" and value == operand:
            return False
        if operator == "$gt" and not (isinstance(value, str) and isinstance(operand, str) and value > operand):
            return False
        if operator == "$regex" and not (isinstance(value, str) and re.search(str(operand), value)):
            return False
    return True


@dataclass
class UserCollection:
    """Documents like {"email", "password_hash", "reset_token", "reset_expires_at"}."""

    documents: list[dict] = field(default_factory=list)

    def find_one(self, query: dict) -> dict | None:
        """First document whose every field matches the query."""
        for document in self.documents:
            matched = True
            for name, condition in query.items():
                if not _matches_condition(document.get(name), condition):
                    matched = False
                    break
            if matched:
                return document
        return None


def hash_password(password: str) -> str:
    """Stand-in for a real password hash; the problem here is the lookup, not hashing."""
    return hashlib.sha256(password.encode()).hexdigest()


def start_reset(users: UserCollection, email: str, clock: Clock) -> str:
    """Create a reset token for ``email`` (normally emailed to the user)."""
    user = users.find_one({"email": email})
    if user is None:
        raise ResetRefused("reset refused")
    token = secrets.token_urlsafe(TOKEN_BYTES)
    user["reset_token"] = token
    user["reset_expires_at"] = clock() + RESET_TOKEN_TTL_S
    return token


# --- the original, vulnerable handler ----------------------------------------
def naive_complete_reset(users: UserCollection, body: dict, clock: Clock) -> str:
    """The bug: request values go into the query as-is, so objects become operators."""
    user = users.find_one({"email": body["email"], "reset_token": body["token"]})
    if user is None:
        raise ResetRefused("reset refused")
    user["password_hash"] = hash_password(body["new_password"])
    user["reset_token"] = None
    return user["email"]


# --- the fix -------------------------------------------------------------------
def parse_reset_body(body: object) -> tuple[str, str, str]:
    """Accept exactly {email, token, new_password}, each a short plain string."""
    if not isinstance(body, dict) or set(body) != RESET_FIELDS:
        raise BadRequest("expected fields: email, token, new_password")
    for name in sorted(RESET_FIELDS):
        value = body[name]
        # WHY: a dict or list here is how operators like {"$ne": null} get in.
        if not isinstance(value, str) or not 0 < len(value) <= MAX_FIELD_LENGTH:
            raise BadRequest(f"{name} must be a non-empty string")
    if len(body["new_password"]) < MIN_PASSWORD_LENGTH:
        raise BadRequest("password too short")
    return body["email"], body["token"], body["new_password"]


def token_is_valid(user: dict, token: str, now: float) -> bool:
    """Check the stored token in code: present, not expired, equal in constant time."""
    stored = user.get("reset_token")
    if not isinstance(stored, str):
        return False
    if now >= user.get("reset_expires_at", 0):
        return False
    return hmac.compare_digest(stored.encode(), token.encode())


def complete_reset(users: UserCollection, body: object, clock: Clock) -> str:
    """Validate the body, look the user up by email only, then verify the token."""
    email, token, new_password = parse_reset_body(body)
    user = users.find_one({"email": email})
    if user is None or not token_is_valid(user, token, clock()):
        raise ResetRefused("reset refused")
    user["password_hash"] = hash_password(new_password)
    # Single use: a token that worked once must never work again.
    user["reset_token"] = None
    return user["email"]
