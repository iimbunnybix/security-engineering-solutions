"""Stop SMS-pumping fraud on the "send login code" endpoint.

The OTP endpoint limited each phone number to 3 codes per hour. Fraudsters
(who share revenue with the carriers that terminate the messages) sent
requests for thousands of *different* numbers in one number range, so no
single number ever hit the limit and the company paid for every SMS. This
module adds the limits that match how the attack works: only countries the
business serves, a cap per number range (prefix), and an hourly global
budget, on top of the per-number limit.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Callable

Clock = Callable[[], float]

WINDOW_SECONDS = 3600
PER_NUMBER_HOURLY_LIMIT = 3
# Real users are spread over many ranges; dozens of codes per hour to one
# 100,000-number block is the signature of pumping.
PER_PREFIX_HOURLY_LIMIT = 20
# Several times normal peak traffic for this app; a hard ceiling on the bill.
GLOBAL_HOURLY_LIMIT = 500
# "+" plus country code 91 plus the first 5 national digits = one block.
PREFIX_LENGTH = 8
ALLOWED_COUNTRY_CODES = ("+91", "+971")


class SmsGateway:
    """Fake SMS provider that records every message we pay for."""

    def __init__(self) -> None:
        self.sent: list[str] = []

    def send(self, phone: str, text: str) -> None:
        """Pretend to send ``text`` to ``phone``."""
        self.sent.append(phone)


class SlidingWindowCounter:
    """Counts events per key within the last WINDOW_SECONDS."""

    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def count(self, key: str) -> int:
        """Number of events for ``key`` still inside the window."""
        timestamps = self.events[key]
        cutoff = self.clock() - WINDOW_SECONDS
        # Drop expired events so the window slides and memory stays bounded.
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        return len(timestamps)

    def record(self, key: str) -> None:
        """Remember one event for ``key`` at the current time."""
        self.events[key].append(self.clock())


class NaiveOtpSender:
    """Original endpoint: only a per-number limit."""

    def __init__(self, gateway: SmsGateway, clock: Clock) -> None:
        self.gateway = gateway
        self.per_number = SlidingWindowCounter(clock)

    def request_code(self, phone: str) -> bool:
        """Send a code unless this exact number had 3 in the last hour."""
        if self.per_number.count(phone) >= PER_NUMBER_HOURLY_LIMIT:
            return False
        self.per_number.record(phone)
        self.gateway.send(phone, "Your login code is ******")
        return True


def is_valid_e164(phone: str) -> bool:
    """True for "+" followed by 8 to 15 ASCII digits."""
    digits = phone[1:]
    return phone.startswith("+") and digits.isascii() and digits.isdigit() and 8 <= len(digits) <= 15


def number_range(phone: str) -> str:
    """The block a number belongs to, e.g. "+9198200" for +919820012345."""
    return phone[:PREFIX_LENGTH]


class OtpSender:
    """Fixed endpoint: country allowlist, per-range, per-number and global caps."""

    def __init__(self, gateway: SmsGateway, clock: Clock) -> None:
        self.gateway = gateway
        self.per_number = SlidingWindowCounter(clock)
        self.per_range = SlidingWindowCounter(clock)
        self.global_count = SlidingWindowCounter(clock)

    def rejection_reason(self, phone: str) -> str | None:
        """Why this request must not cost us an SMS, or None if it may."""
        if not is_valid_e164(phone):
            return "invalid number"
        if not phone.startswith(ALLOWED_COUNTRY_CODES):
            return "country not served"
        if self.per_number.count(phone) >= PER_NUMBER_HOURLY_LIMIT:
            return "number limit"
        if self.per_range.count(number_range(phone)) >= PER_PREFIX_HOURLY_LIMIT:
            return "range limit"
        if self.global_count.count("all") >= GLOBAL_HOURLY_LIMIT:
            return "global budget"
        return None

    def request_code(self, phone: str) -> bool:
        """Send a code if every limit allows it; record it against each limit."""
        if self.rejection_reason(phone) is not None:
            return False
        self.per_number.record(phone)
        self.per_range.record(number_range(phone))
        self.global_count.record("all")
        self.gateway.send(phone, "Your login code is ******")
        return True
