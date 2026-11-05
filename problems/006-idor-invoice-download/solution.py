"""Object-level authorization for an invoice download API (fixes IDOR/BOLA).

The incident: ``GET /api/invoices/<id>`` checked that the caller was logged
in, then returned whatever invoice had that id. Ids were sequential, so a
customer who changed ``10452`` to ``10451`` in the URL got another company's
invoice, and a script downloaded thousands of them.

The fix:

* **Scope every lookup by the caller.** ``InvoiceRepository.get_for(principal,
  id)`` adds the tenant (and, for plain members, ownership) to the query. The
  handler never calls an unscoped "get by id".
* **Deny by default** with an explicit policy per role.
* **Same response for "not found" and "not yours"** (404), so the API is not
  an oracle that confirms which ids exist.
* **Audit and detect enumeration**: every denial is logged; a caller with
  many denials in a short window is flagged (and can be blocked).
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    role: str            # "member" | "billing_admin" | "support"


@dataclass(frozen=True)
class Invoice:
    id: int
    tenant_id: str
    owner_id: str
    amount_cents: int


@dataclass
class Response:
    status: int
    body: object = None


class InvoiceRepository:
    def __init__(self) -> None:
        self._rows: dict[int, Invoice] = {}

    def add(self, inv: Invoice) -> None:
        self._rows[inv.id] = inv

    # The dangerous primitive. Kept private: handlers must not use it.
    def _get_unscoped(self, invoice_id: int) -> Invoice | None:
        return self._rows.get(invoice_id)

    def get_for(self, p: Principal, invoice_id: int) -> Invoice | None:
        """Fetch an invoice only if ``p`` may read it; otherwise None.

        Equivalent SQL: ``... WHERE id = ? AND tenant_id = ? [AND owner_id = ?]``
        so a foreign row is never even loaded.
        """
        inv = self._rows.get(invoice_id)
        if inv is None or not can_read(p, inv):
            return None
        return inv


def can_read(p: Principal, inv: Invoice) -> bool:
    """Deny-by-default read policy."""
    if p.role == "support":
        return False             # support goes through a separate, approved grant flow
    if p.tenant_id != inv.tenant_id:
        return False
    if p.role == "billing_admin":
        return True
    if p.role == "member":
        return inv.owner_id == p.user_id
    return False


def principal_key(p: Principal) -> tuple[str, str]:
    """Globally unique identity of a caller.

    User ids are often only unique inside a tenant, so keying by ``user_id``
    alone would let one tenant's user lock out a same-named user elsewhere.
    """
    return (p.tenant_id, p.user_id)


class AccessAudit:
    """Records denials and flags callers who look like they are enumerating."""

    def __init__(self, threshold: int = 20, window_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic):
        self.threshold, self.window_s, self.clock = threshold, window_s, clock
        self._denials: dict[tuple[str, str], deque] = defaultdict(deque)
        self.log: list[dict] = []
        self.flagged: set[tuple[str, str]] = set()

    def denied(self, p: Principal, invoice_id: int) -> None:
        now = self.clock()
        self.log.append({"t": now, "user": p.user_id, "tenant": p.tenant_id,
                         "action": "invoice.read", "object": invoice_id, "result": "denied"})
        # Count per (tenant, user), not per user_id: see principal_key.
        q = self._denials[principal_key(p)]
        q.append(now)
        while q and q[0] <= now - self.window_s:
            q.popleft()
        if len(q) >= self.threshold:
            self.flagged.add(principal_key(p))

    def is_blocked(self, p: Principal) -> bool:
        return principal_key(p) in self.flagged


def get_invoice_vulnerable(repo: InvoiceRepository, p: Principal | None,
                           invoice_id: int) -> Response:
    """The original handler: authentication only."""
    if p is None:
        return Response(401)
    inv = repo._get_unscoped(invoice_id)
    return Response(200, inv) if inv else Response(404)


def get_invoice(repo: InvoiceRepository, audit: AccessAudit, p: Principal | None,
                invoice_id: int) -> Response:
    """Fixed handler: scoped lookup, uniform 404, audit, enumeration block."""
    if p is None:
        return Response(401)
    if audit.is_blocked(p):
        return Response(429, "too many failed lookups; contact support")
    inv = repo.get_for(p, invoice_id)
    if inv is None:
        audit.denied(p, invoice_id)
        return Response(404)
    return Response(200, inv)
