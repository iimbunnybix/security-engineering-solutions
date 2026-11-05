"""Attempt limits for 6-digit MFA codes, so they cannot be brute-forced.

After a correct password, the login flow sends a 6-digit code by SMS and
creates an MFA challenge valid for 5 minutes. The original verify endpoint
let a client guess the code for a challenge as many times as it liked, and
just as many new challenges per account. An attacker who already had the
password scripted guesses and got in within the validity window: there are
only 1,000,000 possible codes, and N distinct guesses succeed with
probability N / 1,000,000.

The fix caps wrong guesses per challenge (the 5th failure destroys the
challenge), caps failures per account across all challenges in a rolling
24 h window, compares codes in constant time, and makes codes single-use.
"""
from __future__ import annotations

import hmac
import secrets
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

CODE_DIGITS = 6
CODE_SPACE = 10 ** CODE_DIGITS                 # 1,000,000 possible codes
CODE_TTL_S = 5 * 60
MAX_ATTEMPTS_PER_CHALLENGE = 5
MAX_ACCOUNT_FAILURES = 10
ACCOUNT_FAILURE_WINDOW_S = 24 * 3600

Clock = Callable[[], float]
CodeGenerator = Callable[[], str]


def random_code() -> str:
    """A uniformly random 6-digit code from the OS CSPRNG."""
    return f"{secrets.randbelow(CODE_SPACE):0{CODE_DIGITS}d}"


def guess_probability(distinct_guesses: int) -> float:
    """Chance that ``distinct_guesses`` different guesses hit one random code."""
    return min(distinct_guesses, CODE_SPACE) / CODE_SPACE


# --- original version ---------------------------------------------------
class NaiveMfaVerifier:
    """The bug: no attempt counting, plain ``==``, codes reusable until expiry."""

    def __init__(self, clock: Clock, make_code: CodeGenerator = random_code) -> None:
        self.clock = clock
        self.make_code = make_code
        self.challenges: dict[str, tuple[str, str, float]] = {}   # id -> (user, code, expires)

    def start(self, user: str) -> str:
        challenge_id = secrets.token_urlsafe(16)
        self.challenges[challenge_id] = (user, self.make_code(), self.clock() + CODE_TTL_S)
        return challenge_id

    def verify(self, challenge_id: str, code: str) -> bool:
        _user, expected, expires_at = self.challenges[challenge_id]
        return self.clock() < expires_at and code == expected


# --- fixed version ------------------------------------------------------
@dataclass
class Challenge:
    user: str
    code: str
    expires_at: float
    wrong_attempts: int = 0


@dataclass
class MfaVerifier:
    clock: Clock
    make_code: CodeGenerator = random_code
    challenges: dict[str, Challenge] = field(default_factory=dict)
    failures_by_user: dict[str, deque] = field(default_factory=dict)

    def start(self, user: str) -> str:
        """Create a challenge (and send its code). Refused while the account is locked."""
        if self.account_locked(user):
            raise PermissionError("too many failed MFA attempts; account locked")
        challenge_id = secrets.token_urlsafe(16)
        self.challenges[challenge_id] = Challenge(user, self.make_code(), self.clock() + CODE_TTL_S)
        return challenge_id

    def account_locked(self, user: str) -> bool:
        """True if ``user`` has used up their failure budget in the window."""
        return len(self._recent_failures(user)) >= MAX_ACCOUNT_FAILURES

    def _recent_failures(self, user: str) -> deque:
        """The user's failure timestamps, with ones older than the window dropped."""
        failures = self.failures_by_user.setdefault(user, deque())
        window_start = self.clock() - ACCOUNT_FAILURE_WINDOW_S
        while failures and failures[0] <= window_start:
            failures.popleft()
        return failures

    def verify(self, challenge_id: str, code: str) -> bool:
        """Check a code. Every outcome except a wrong guess on a live challenge ends it."""
        challenge = self.challenges.get(challenge_id)
        if challenge is None:
            return False
        if self.clock() >= challenge.expires_at or self.account_locked(challenge.user):
            del self.challenges[challenge_id]
            return False
        if self._code_matches(challenge.code, code):
            # Single use: a code that worked once can never work again.
            del self.challenges[challenge_id]
            return True
        self._record_failure(challenge_id, challenge)
        return False

    def _code_matches(self, expected: str, submitted: str) -> bool:
        """Constant-time comparison of a well-formed 6-digit submission."""
        if len(submitted) != CODE_DIGITS or not submitted.isascii() or not submitted.isdigit():
            return False
        # compare_digest takes the same time wherever the first difference is,
        # so response timing does not reveal how many leading digits are right.
        return hmac.compare_digest(expected.encode("ascii"), submitted.encode("ascii"))

    def _record_failure(self, challenge_id: str, challenge: Challenge) -> None:
        """Count a wrong guess against the challenge and the account."""
        challenge.wrong_attempts += 1
        self._recent_failures(challenge.user).append(self.clock())
        # Destroy the challenge, not just block it: the attacker must get a
        # new code sent, which is visible to the real user and rate limited.
        if challenge.wrong_attempts >= MAX_ATTEMPTS_PER_CHALLENGE:
            del self.challenges[challenge_id]
