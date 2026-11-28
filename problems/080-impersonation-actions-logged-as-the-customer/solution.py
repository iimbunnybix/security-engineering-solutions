"""Record who really acted when support staff impersonate a customer.

Support could "log in as" a customer to reproduce bugs. The impersonation
session was an ordinary session for the customer's user id, so every action
in it, including changing the payout bank account, was written to the audit
log as done by the customer. When a payout was redirected, the log blamed
the customer and could not show which agent did it.

Fix: an impersonation session carries both the subject (the customer) and the
actor (the staff member). Audit entries record both, impersonation start is
logged with a ticket reference, and security-sensitive actions are refused
while impersonating.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Actions that change who controls the account or where money goes.
SENSITIVE_ACTIONS = {"change_payout_account", "change_password", "change_email", "disable_mfa"}


class ImpersonationForbidden(PermissionError):
    """A sensitive action was attempted from an impersonation session."""


@dataclass(frozen=True)
class AuditEntry:
    action: str
    subject_id: str                 # whose account the action affected
    actor_id: str                   # who actually performed it
    impersonated: bool
    detail: str = ""


@dataclass(frozen=True)
class Session:
    subject_id: str
    actor_id: str

    @property
    def is_impersonation(self) -> bool:
        return self.actor_id != self.subject_id


@dataclass
class AccountService:
    payout_accounts: dict[str, str] = field(default_factory=dict)
    audit_log: list[AuditEntry] = field(default_factory=list)

    # ---- original ----------------------------------------------------------
    def original_impersonate(self, staff_id: str, customer_id: str) -> Session:
        """Original: a plain session for the customer; the staff id is dropped."""
        return Session(subject_id=customer_id, actor_id=customer_id)

    def original_change_payout(self, session: Session, new_account: str) -> None:
        self.payout_accounts[session.subject_id] = new_account
        self.audit_log.append(AuditEntry("change_payout_account", session.subject_id,
                                         session.actor_id, impersonated=False))

    # ---- fixed -------------------------------------------------------------
    def impersonate(self, staff_id: str, customer_id: str, ticket: str) -> Session:
        """Start an impersonation session; a support ticket reference is required."""
        if not ticket.strip():
            raise ValueError("impersonation needs a support ticket reference")
        if staff_id == customer_id:
            raise ValueError("cannot impersonate yourself")
        session = Session(subject_id=customer_id, actor_id=staff_id)
        self._audit(session, "impersonation_started", detail=f"ticket={ticket}")
        return session

    def change_payout(self, session: Session, new_account: str) -> None:
        """Change where the customer's money is paid out."""
        self._require_not_impersonating(session, "change_payout_account")
        self.payout_accounts[session.subject_id] = new_account
        self._audit(session, "change_payout_account")

    def view_orders(self, session: Session) -> str:
        """A harmless read support needs while debugging; still audited."""
        self._audit(session, "view_orders")
        return f"orders of {session.subject_id}"

    def _require_not_impersonating(self, session: Session, action: str) -> None:
        """Refuse a sensitive action from an impersonation session, and log the attempt."""
        if session.is_impersonation and action in SENSITIVE_ACTIONS:
            # WHY: a refused attempt is exactly what an investigator wants to see.
            self._audit(session, action, detail="refused: impersonation session")
            raise ImpersonationForbidden(f"{action} is not allowed while impersonating")

    def _audit(self, session: Session, action: str, detail: str = "") -> None:
        self.audit_log.append(AuditEntry(action, session.subject_id, session.actor_id,
                                         session.is_impersonation, detail))


def actions_by(audit_log: list[AuditEntry], actor_id: str) -> list[str]:
    """What an investigator asks first: everything this person did."""
    actions = []
    for entry in audit_log:
        if entry.actor_id == actor_id:
            actions.append(entry.action)
    return actions
