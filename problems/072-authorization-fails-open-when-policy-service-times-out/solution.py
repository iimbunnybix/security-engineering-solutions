"""Stop authorization from granting everything when the policy service is down.

Every API request asked a central policy service "may this user do this
action on this resource?". To avoid blocking users during outages, the
client caught any error and returned "allowed", and it treated a reply
without an ``allow`` field as a yes. When the policy service timed out for
twenty minutes, every request was allowed, including those of users whose
access had been revoked.

The fix fails closed: only a well-formed reply with ``allow`` exactly
``True`` grants access, and any error or odd reply denies. To keep normal
users working through short blips, a recent *allow* for the same
(user, action, resource) may be reused for a bounded grace period.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

Clock = Callable[[], float]

# How long a fresh allow decision is reused without asking again.
DECISION_CACHE_TTL_S = 30.0
# During an outage, how old a cached allow may be and still be honoured.
# This is also the longest a revocation can be ignored while the service is down.
OUTAGE_GRACE_S = 120.0


class PolicyUnavailable(Exception):
    """The policy service timed out, refused the connection or returned 5xx."""


class PolicyService(Protocol):
    def check(self, user: str, action: str, resource: str) -> object:
        """Return the decoded JSON reply, e.g. {"allow": True}, or raise PolicyUnavailable."""


@dataclass(frozen=True)
class Request:
    user: str
    action: str
    resource: str


# --- the original, fail-open client ------------------------------------------
def naive_authorize(service: PolicyService, request: Request) -> bool:
    """The bug: errors, replies without "allow" and truthy non-booleans all mean "allowed"."""
    try:
        reply = service.check(request.user, request.action, request.resource)
    except Exception:
        # "Don't block customers because of our outage" -- which also unblocks attackers.
        return True
    if isinstance(reply, dict):
        # Missing field defaults to True; the string "false" is truthy too.
        return bool(reply.get("allow", True))
    return True


# --- the fix -------------------------------------------------------------------
def is_explicit_allow(reply: object) -> bool:
    """Grant only for a dict whose "allow" is exactly True (not 1, "true" or missing)."""
    return isinstance(reply, dict) and reply.get("allow") is True


class FailClosedAuthorizer:
    """Asks the policy service; denies on any failure unless a recent allow exists."""

    def __init__(self, service: PolicyService, clock: Clock) -> None:
        self.service = service
        self.clock = clock
        # (user, action, resource) -> time of the last explicit allow.
        self.last_allowed_at: dict[tuple[str, str, str], float] = {}
        self.denied_because_unavailable = 0

    def authorize(self, request: Request) -> bool:
        """True only when the service says allow, or recently did and is now unreachable."""
        key = (request.user, request.action, request.resource)
        now = self.clock()
        if self._cached_allow_age(key, now) < DECISION_CACHE_TTL_S:
            return True
        try:
            reply = self.service.check(request.user, request.action, request.resource)
        except PolicyUnavailable:
            return self._decide_during_outage(key, now)
        if is_explicit_allow(reply):
            self.last_allowed_at[key] = now
            return True
        # WHY forget: an explicit deny (or a reply we cannot read) must not be
        # overridden later by an older allow if the service then goes down.
        self.last_allowed_at.pop(key, None)
        return False

    def _cached_allow_age(self, key: tuple[str, str, str], now: float) -> float:
        """Seconds since the last allow for this key (infinity if none)."""
        allowed_at = self.last_allowed_at.get(key)
        if allowed_at is None:
            return float("inf")
        return now - allowed_at

    def _decide_during_outage(self, key: tuple[str, str, str], now: float) -> bool:
        """Honour a recent allow for a short grace period, otherwise deny (fail closed)."""
        if self._cached_allow_age(key, now) <= OUTAGE_GRACE_S:
            return True
        self.denied_because_unavailable += 1
        return False
