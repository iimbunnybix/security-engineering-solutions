"""Refuse passwords that already appear in public breach dumps.

The sign-up form required 8+ characters with an upper-case letter, a
lower-case letter and a digit. "Password1" and "Welcome@123" pass those
rules and are also near the top of every leaked-password list, so
credential-stuffing bots logged in to thousands of new accounts on the first
try.

The fix drops the composition rules for a length minimum and checks every
new password against a breached-password corpus using k-anonymity: only the
first 5 hex characters of the password's SHA-1 hash leave the server, the
service returns every breached hash suffix with that prefix, and the match is
done locally. If the breach service is down, a small built-in list of the
most common passwords is used instead of skipping the check.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

MIN_PASSWORD_LENGTH = 12
HASH_PREFIX_LENGTH = 5
# Fallback for outages: a handful of the most common leaked passwords.
LOCAL_COMMON_PASSWORDS = {"123456789012", "password1234", "qwertyuiop12", "welcome@1234"}


class BreachServiceUnavailable(Exception):
    """The breached-password range service could not be reached."""


class BreachRangeService(Protocol):
    def suffixes_for_prefix(self, prefix: str) -> dict[str, int]:
        """All breached SHA-1 suffixes (upper-case hex) starting with prefix, with counts."""


@dataclass(frozen=True)
class PasswordDecision:
    accepted: bool
    reason: str
    breach_checked: bool = True


def naive_password_ok(password: str) -> bool:
    """The original rule: 8+ characters with upper, lower and a digit."""
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_digit = any(char.isdigit() for char in password)
    return len(password) >= 8 and has_upper and has_lower and has_digit


def sha1_hex(password: str) -> str:
    """Upper-case hex SHA-1, the format breach corpora are published in.

    SHA-1 is used only to look the password up, never to store it.
    """
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def breach_count(password: str, service: BreachRangeService) -> int:
    """How often the password appears in breaches, sending only a hash prefix."""
    full_hash = sha1_hex(password)
    prefix = full_hash[:HASH_PREFIX_LENGTH]
    suffix = full_hash[HASH_PREFIX_LENGTH:]
    # The service never learns which of the returned suffixes we cared about.
    return service.suffixes_for_prefix(prefix).get(suffix, 0)


def basic_problem(password: str, username: str) -> str | None:
    """Length and username checks that need no network call."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"use at least {MIN_PASSWORD_LENGTH} characters"
    if username and username.casefold() in password.casefold():
        return "password must not contain your username"
    return None


def check_new_password(password: str, username: str, service: BreachRangeService) -> PasswordDecision:
    """Decide whether a password may be set at sign-up or password change."""
    problem = basic_problem(password, username)
    if problem is not None:
        return PasswordDecision(False, problem)
    try:
        times_seen = breach_count(password, service)
    except BreachServiceUnavailable:
        return check_while_service_down(password)
    if times_seen > 0:
        return PasswordDecision(False, f"this password appeared in {times_seen} data breaches")
    return PasswordDecision(True, "ok")


def check_while_service_down(password: str) -> PasswordDecision:
    """Fallback: local list only, and flag the account for a re-check later.

    Blocking every sign-up during an outage is worse than a short window of
    weaker checking, but the gap must be visible, not silent.
    """
    if password.casefold() in LOCAL_COMMON_PASSWORDS:
        return PasswordDecision(False, "this password is too common", breach_checked=False)
    return PasswordDecision(True, "accepted without breach check", breach_checked=False)


class FakeBreachRangeService:
    """In-memory stand-in for a range API built from a list of leaked passwords."""

    def __init__(self, leaked_counts: dict[str, int]) -> None:
        self._suffixes_by_prefix: dict[str, dict[str, int]] = {}
        for password, count in leaked_counts.items():
            full_hash = sha1_hex(password)
            bucket = self._suffixes_by_prefix.setdefault(full_hash[:HASH_PREFIX_LENGTH], {})
            bucket[full_hash[HASH_PREFIX_LENGTH:]] = count
        self.queried_prefixes: list[str] = []
        self.available = True

    def suffixes_for_prefix(self, prefix: str) -> dict[str, int]:
        if not self.available:
            raise BreachServiceUnavailable("range service timed out")
        self.queried_prefixes.append(prefix)
        return dict(self._suffixes_by_prefix.get(prefix, {}))
