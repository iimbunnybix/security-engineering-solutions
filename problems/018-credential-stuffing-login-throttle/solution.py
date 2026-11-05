"""Login throttling that stops credential stuffing without locking out real users.

The original login endpoint checked the password and nothing else, so a bot
with a leaked list of email/password pairs could try thousands of pairs per
minute and take over every account that reused a password. This module counts
failed logins per account and per client IP and makes each key wait
exponentially longer after a few free failures. The wait is capped and resets
on success, and an IP that has logged in to an account before skips that
account's throttle, so an attacker cannot lock the real owner out.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

FREE_FAILURES = 5                    # typos are normal; do not punish them
BASE_DELAY_SECONDS = 1.0
MAX_DELAY_SECONDS = 15 * 60          # a cap, not a permanent lock
FORGET_FAILURES_AFTER_SECONDS = 60 * 60


class LoginOutcome(Enum):
    SUCCESS = "success"
    WRONG_PASSWORD = "wrong_password"
    THROTTLED = "throttled"


@dataclass
class LoginResult:
    outcome: LoginOutcome
    retry_after_seconds: float = 0.0


class FakeClock:
    """A clock the tests move forward by hand, so backoff is deterministic."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class FailureRecord:
    """Consecutive failures for one key (an account or an IP)."""
    count: int = 0
    last_failure_at: float = 0.0


def backoff_delay(failure_count: int) -> float:
    """Seconds a key must wait after this many consecutive failures."""
    if failure_count < FREE_FAILURES:
        return 0.0
    # Doubling per failure makes guessing very slow, while the cap keeps a
    # throttled real user's worst-case wait bounded.
    exponent = failure_count - FREE_FAILURES
    return min(BASE_DELAY_SECONDS * (2 ** exponent), MAX_DELAY_SECONDS)


def naive_login(passwords: dict[str, str], email: str, password: str) -> LoginOutcome:
    """The original endpoint: no limit on how fast or how often anyone can guess."""
    if passwords.get(email) == password:
        return LoginOutcome.SUCCESS
    return LoginOutcome.WRONG_PASSWORD


@dataclass
class FailureTracker:
    """Failure counters keyed by a string, with exponential backoff."""
    clock: FakeClock
    records: dict[str, FailureRecord] = field(default_factory=dict)

    def seconds_until_allowed(self, key: str) -> float:
        record = self.records.get(key)
        if record is None:
            return 0.0
        wait_until = record.last_failure_at + backoff_delay(record.count)
        return max(0.0, wait_until - self.clock.time())

    def record_failure(self, key: str) -> None:
        record = self.records.setdefault(key, FailureRecord())
        # Failures spread over a long time are not an attack; start over.
        if self.clock.time() - record.last_failure_at > FORGET_FAILURES_AFTER_SECONDS:
            record.count = 0
        record.count += 1
        record.last_failure_at = self.clock.time()

    def reset(self, key: str) -> None:
        self.records.pop(key, None)


class ThrottledLoginService:
    """Login with per-account and per-IP backoff, and trusted IPs per account."""

    def __init__(self, passwords: dict[str, str], clock: FakeClock) -> None:
        self.passwords = passwords
        self.account_failures = FailureTracker(clock)
        self.ip_failures = FailureTracker(clock)
        self.trusted_ips: dict[str, set[str]] = {}

    def _wait_seconds(self, email: str, client_ip: str) -> float:
        """How long this request must wait, combining both throttles."""
        ip_wait = self.ip_failures.seconds_until_allowed(client_ip)
        # An IP the owner has used before is not throttled by failures that
        # other IPs caused on the account; this is what stops attacker lockout.
        if client_ip in self.trusted_ips.get(email, set()):
            return ip_wait
        account_wait = self.account_failures.seconds_until_allowed(email)
        return max(ip_wait, account_wait)

    def login(self, email: str, password: str, client_ip: str) -> LoginResult:
        wait = self._wait_seconds(email, client_ip)
        # Check the throttle before the password, otherwise a throttled
        # attacker could still learn which guess was right.
        if wait > 0:
            return LoginResult(LoginOutcome.THROTTLED, retry_after_seconds=wait)
        if self.passwords.get(email) == password:
            self.account_failures.reset(email)
            self.ip_failures.reset(client_ip)
            self.trusted_ips.setdefault(email, set()).add(client_ip)
            return LoginResult(LoginOutcome.SUCCESS)
        self.account_failures.record_failure(email)
        self.ip_failures.record_failure(client_ip)
        return LoginResult(LoginOutcome.WRONG_PASSWORD)
