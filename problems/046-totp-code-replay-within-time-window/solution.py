"""Two-factor login that refuses a TOTP code that was already used.

A brokerage app verified 6-digit TOTP codes (RFC 6238) by checking that the
code matched the current 30-second step or one step either side for clock
drift. Nothing remembered which codes had been used, so a code captured by a
phishing proxy or read over a shoulder stayed valid for up to 90 seconds and
could log the attacker in right after the victim. This module stores, per
user, the last time step that was accepted and only accepts a strictly later
step, so every code works at most once.
"""
from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field
from typing import Callable

TIME_STEP_SECONDS = 30
CODE_DIGITS = 6
# Accept one step before and after the current one for phone clock drift.
ALLOWED_DRIFT_STEPS = 1
# RFC 4226 dynamic truncation: low 4 bits of the last byte pick an offset,
# and the top bit of the 31-bit result is masked off.
TRUNCATION_OFFSET_MASK = 0x0F
TRUNCATION_VALUE_MASK = 0x7FFFFFFF

Clock = Callable[[], float]


def hotp(secret: bytes, counter: int) -> str:
    """RFC 4226 one-time code for a counter value, zero-padded."""
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & TRUNCATION_OFFSET_MASK
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & TRUNCATION_VALUE_MASK
    return str(value % 10 ** CODE_DIGITS).zfill(CODE_DIGITS)


def time_step(unix_time: float) -> int:
    """Which 30-second window a moment falls in (RFC 6238 'T')."""
    return int(unix_time // TIME_STEP_SECONDS)


def matching_step(secret: bytes, code: str, unix_time: float) -> int | None:
    """Return the time step within the drift window whose code equals `code`."""
    current = time_step(unix_time)
    for step in range(current - ALLOWED_DRIFT_STEPS, current + ALLOWED_DRIFT_STEPS + 1):
        # Constant-time compare so timing does not reveal matching digits.
        if hmac.compare_digest(hotp(secret, step).encode(), code.encode()):
            return step
    return None


def is_well_formed(code: str) -> bool:
    """Only exactly six ASCII digits can be a code."""
    return len(code) == CODE_DIGITS and code.isascii() and code.isdigit()


# --------------------------------------------------------------------------
# ORIGINAL verifier
# --------------------------------------------------------------------------

@dataclass
class NaiveTotpVerifier:
    """ORIGINAL: any code valid in the drift window is accepted, every time."""

    secrets_by_user: dict[str, bytes]
    clock: Clock

    def verify(self, user_id: str, code: str) -> bool:
        """True when the code matches; the same code can be used repeatedly."""
        secret = self.secrets_by_user[user_id]
        if not is_well_formed(code):
            return False
        return matching_step(secret, code, self.clock()) is not None


# --------------------------------------------------------------------------
# FIX: remember the last accepted step per user
# --------------------------------------------------------------------------

@dataclass
class TotpVerifier:
    """FIX: a code is accepted only if its step is later than the last one used."""

    secrets_by_user: dict[str, bytes]
    clock: Clock
    last_used_step: dict[str, int] = field(default_factory=dict)

    def verify(self, user_id: str, code: str) -> bool:
        """True at most once per code, and never for a step older than one already used."""
        secret = self.secrets_by_user[user_id]
        if not is_well_formed(code):
            return False
        step = matching_step(secret, code, self.clock())
        if step is None:
            return False
        # "Strictly greater" rejects the same code again and also an older
        # code from the drift window once a newer one has been accepted.
        previous = self.last_used_step.get(user_id)
        if previous is not None and step <= previous:
            return False
        self.last_used_step[user_id] = step
        return True
