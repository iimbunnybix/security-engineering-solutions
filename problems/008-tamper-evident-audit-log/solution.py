"""Tamper-evident audit log using an HMAC hash chain plus external checkpoints.

The original problem: admin actions (role grants, payout-account changes,
data exports) were written to an ``audit_log`` table that the application's
own database user could UPDATE and DELETE. During an internal investigation
the team could not prove whether rows had been edited or removed, so the log
was useless as evidence, and an auditor flagged it.

Fix:
* Each entry stores ``mac = HMAC(key, canonical(entry) || prev_mac)``, chaining
  every entry to the one before it. Editing, deleting, inserting or
  reordering any entry breaks verification from that point on.
* The HMAC key lives outside the database (a KMS/secret store), so someone with
  only DB access cannot recompute valid MACs.
* The latest ``(seq, mac)`` is periodically copied to a separate write-once
  store as a checkpoint. That detects *truncation* of the tail, which a chain
  alone cannot.
* Entries carry a ``key_id`` so keys can be rotated without breaking old
  entries.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass

GENESIS = "0" * 64


@dataclass(frozen=True)
class Entry:
    seq: int
    ts: float
    actor: str
    action: str
    target: str
    details: dict
    key_id: str
    prev_mac: str
    mac: str


def _canonical(seq, ts, actor, action, target, details, key_id, prev_mac) -> bytes:
    """Deterministic serialization: sorted keys, no whitespace, UTF-8."""
    return json.dumps({"seq": seq, "ts": ts, "actor": actor, "action": action, "target": target,
                       "details": details, "key_id": key_id, "prev_mac": prev_mac},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _mac(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    first_bad_seq: int | None = None
    reason: str = ""


class AuditLog:
    def __init__(self, keys: dict[str, bytes], active_key_id: str):
        if active_key_id not in keys:
            raise ValueError("active key id not in keyring")
        self.keys = dict(keys)
        self.active_key_id = active_key_id
        # key_id -> last seq that key was allowed to sign. A rotated-away key
        # may have leaked, so entries it signs after retirement are forgeries.
        self.retired_after: dict[str, int] = {}
        self.entries: list[Entry] = []        # stands in for the DB table
        self.checkpoints: list[tuple[int, str]] = []   # stands in for write-once storage

    def rotate_key(self, key_id: str, key: bytes) -> None:
        # Reusing an id would overwrite the old key and break every old entry.
        if key_id in self.keys:
            raise ValueError("key id already exists; use a new id")
        self.retired_after[self.active_key_id] = len(self.entries)
        self.keys[key_id] = key
        self.active_key_id = key_id

    def append(self, ts: float, actor: str, action: str, target: str, details: dict | None = None) -> Entry:
        details = dict(details or {})
        seq = len(self.entries) + 1
        prev = self.entries[-1].mac if self.entries else GENESIS
        kid = self.active_key_id
        mac = _mac(self.keys[kid], _canonical(seq, ts, actor, action, target, details, kid, prev))
        e = Entry(seq, ts, actor, action, target, details, kid, prev, mac)
        self.entries.append(e)
        return e

    def checkpoint(self) -> tuple[int, str]:
        """Publish the chain head to storage the DB user cannot modify."""
        head = (self.entries[-1].seq, self.entries[-1].mac) if self.entries else (0, GENESIS)
        self.checkpoints.append(head)
        return head

    def verify(self, entries: list[Entry] | None = None) -> VerifyResult:
        entries = self.entries if entries is None else entries
        prev, expected_seq = GENESIS, 1
        by_seq = {}
        for e in entries:
            if e.seq != expected_seq:
                return VerifyResult(False, e.seq, f"sequence gap: expected {expected_seq}")
            if e.prev_mac != prev:
                return VerifyResult(False, e.seq, "chain broken: prev_mac does not match")
            key = self.keys.get(e.key_id)
            if key is None:
                return VerifyResult(False, e.seq, f"unknown key id {e.key_id!r}")
            last_allowed = self.retired_after.get(e.key_id)
            if last_allowed is not None and e.seq > last_allowed:
                return VerifyResult(False, e.seq, "entry signed with a retired key")
            want = _mac(key, _canonical(e.seq, e.ts, e.actor, e.action, e.target, e.details,
                                         e.key_id, e.prev_mac))
            if not hmac.compare_digest(want, e.mac):
                return VerifyResult(False, e.seq, "MAC mismatch: entry content was modified")
            by_seq[e.seq] = e.mac
            prev, expected_seq = e.mac, expected_seq + 1
        for seq, mac in self.checkpoints:
            if seq == 0:
                continue
            if seq not in by_seq:
                return VerifyResult(False, seq, "truncated: checkpointed entry is missing")
            if not hmac.compare_digest(by_seq[seq], mac):
                return VerifyResult(False, seq, "checkpoint mismatch: history was rewritten")
        return VerifyResult(True)


def plain_log_detects_tampering(original: list[dict], current: list[dict]) -> bool:
    """The original table had no integrity data: the only 'check' possible is
    whether the rows look well-formed, which edits and deletions preserve."""
    required = {"ts", "actor", "action", "target"}
    return not all(required <= set(r) for r in current)
