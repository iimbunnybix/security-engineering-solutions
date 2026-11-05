"""Webhook verification that rejects replayed deliveries.

A payout platform accepted webhooks signed as ``HMAC(secret, body)``. The
signature proved the body came from the provider, but nothing tied it to a
moment in time, so a captured delivery stayed valid forever. Once the
receiver's dedup table had been purged, replaying an old "payout approved"
event paid the same payout again.

The fix signs ``"<timestamp>.<body>"``, rejects deliveries outside a short
tolerance window, and remembers event ids seen inside that window. Because old
timestamps are refused, the replay cache only has to cover the window, so it
can never be "purged too early". Comparisons are constant time and several
secrets are accepted at once so the signing secret can be rotated.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Callable

TOLERANCE_SECONDS = 300            # 5 minutes either side of our clock
NAIVE_DEDUP_RETENTION_SECONDS = 7 * 24 * 3600

Clock = Callable[[], float]


def hmac_hex(secret: bytes, message: str) -> str:
    """Hex HMAC-SHA256 of a message."""
    return hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()


def event_id_of(body: str) -> str | None:
    """Pull the provider's event id out of a JSON body; None if unreadable."""
    try:
        event = json.loads(body)
    except ValueError:
        return None
    if not isinstance(event, dict) or not isinstance(event.get("id"), str):
        return None
    return event["id"]


# --------------------------------------------------------------------------
# ORIGINAL receiver
# --------------------------------------------------------------------------

def naive_sign(secret: bytes, body: str) -> str:
    """ORIGINAL sender: signs the body only, with no timestamp."""
    return hmac_hex(secret, body)


@dataclass
class NaiveWebhookReceiver:
    """ORIGINAL receiver: valid signature + not in a dedup table that expires."""

    secret: bytes
    clock: Clock
    seen_until: dict[str, float] = field(default_factory=dict)

    def receive(self, body: str, signature: str) -> bool:
        """Return True when the event should be processed (a payout made)."""
        self._purge_old_entries()
        if hmac_hex(self.secret, body) != signature:
            return False
        event_id = event_id_of(body)
        if event_id is None or event_id in self.seen_until:
            return False
        self.seen_until[event_id] = self.clock() + NAIVE_DEDUP_RETENTION_SECONDS
        return True

    def _purge_old_entries(self) -> None:
        """Retention job: the table cannot grow forever, so old ids are dropped."""
        now = self.clock()
        for event_id in [eid for eid, until in self.seen_until.items() if until <= now]:
            del self.seen_until[event_id]


# --------------------------------------------------------------------------
# FIX: timestamped signatures, tolerance window and a replay cache
# --------------------------------------------------------------------------

def sign_delivery(secrets_to_sign_with: list[bytes], body: str, timestamp: int) -> str:
    """Sender: build the header ``t=<ts>,v1=<sig>[,v1=<sig>...]``.

    During a rotation the provider signs with both the old and new secret so
    receivers on either secret keep working.
    """
    signed_payload = f"{timestamp}.{body}"
    parts = [f"t={timestamp}"]
    for secret in secrets_to_sign_with:
        parts.append(f"v1={hmac_hex(secret, signed_payload)}")
    return ",".join(parts)


def parse_signature_header(header: str) -> tuple[int, list[str]] | None:
    """Return (timestamp, signatures) or None when the header is malformed."""
    timestamp = None
    signatures = []
    for part in header.split(","):
        name, separator, value = part.partition("=")
        if not separator:
            return None
        if name == "t" and value.isdigit():
            timestamp = int(value)
        elif name == "v1":
            signatures.append(value)
    if timestamp is None or not signatures:
        return None
    return timestamp, signatures


class Rejected(Exception):
    """Raised with a short reason; the HTTP layer answers 400 and logs it."""


@dataclass
class WebhookReceiver:
    """FIX: verifies signature, freshness and uniqueness before processing."""

    active_secrets: list[bytes]
    clock: Clock
    replay_cache: dict[str, float] = field(default_factory=dict)

    def receive(self, body: str, header: str) -> str:
        """Return the event id to process, or raise Rejected."""
        parsed = parse_signature_header(header)
        if parsed is None:
            raise Rejected("malformed signature header")
        timestamp, signatures = parsed
        self._check_freshness(timestamp)
        if not self._signature_matches(f"{timestamp}.{body}", signatures):
            raise Rejected("bad signature")
        event_id = event_id_of(body)
        if event_id is None:
            raise Rejected("missing event id")
        self._remember_or_reject(event_id, timestamp)
        return event_id

    def _check_freshness(self, timestamp: int) -> None:
        """Old deliveries are refused, which is what bounds the replay cache."""
        # abs(): a timestamp far in the future would otherwise stay "fresh"
        # for longer than the replay cache remembers it.
        if abs(self.clock() - timestamp) > TOLERANCE_SECONDS:
            raise Rejected("timestamp outside tolerance")

    def _signature_matches(self, signed_payload: str, signatures: list[str]) -> bool:
        """True if any presented signature matches any active secret."""
        for secret in self.active_secrets:
            expected = hmac_hex(secret, signed_payload)
            for presented in signatures:
                if hmac.compare_digest(expected, presented):
                    return True
        return False

    def _remember_or_reject(self, event_id: str, timestamp: int) -> None:
        """Reject an event id already accepted while its timestamp is fresh."""
        now = self.clock()
        # Keep an entry while its timestamp could still pass the freshness
        # check (until timestamp + tolerance, inclusive). After that the
        # timestamp check alone rejects the replay, so the entry can go.
        for seen_id in [eid for eid, until in self.replay_cache.items() if until < now]:
            del self.replay_cache[seen_id]
        if event_id in self.replay_cache:
            raise Rejected("replayed event")
        self.replay_cache[event_id] = timestamp + TOLERANCE_SECONDS
