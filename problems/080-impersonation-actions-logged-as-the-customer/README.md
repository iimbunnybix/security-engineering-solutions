# 080 · A seller's payouts went to a stranger's bank account, and the audit log said the seller changed it themselves

## Problem
A marketplace lets its support team "log in as" a seller to reproduce bugs
the seller reports. About 60 agents use it daily.

A seller reported that two weeks of payouts had gone to a bank account they
did not own. The audit log showed `change_payout_account` performed by the
seller's own user id, from an office IP address. The seller was told it
looked like their own action; they escalated, and only after a week of
cross-checking support tooling logs did the security team find that a
support agent, impersonating the seller to "check a payout bug", had changed
the account. Similar changes on three other sellers could not be attributed
to anyone.

## Root cause
Impersonation created an **ordinary session for the seller**. The session
held only the seller's user id, and the staff member's id was thrown away
when it was created. Every action in that session was, as far as the
application could tell, done by the seller:
- the audit log recorded the seller as the actor, with no impersonation flag;
- a search for "everything this agent did" returned nothing;
- the session had every power the seller had, including changing the payout
  account.

## Solution
- An impersonation `Session` carries **two ids**: `subject_id` (the
  account being acted on) and `actor_id` (the staff member). Every
  `AuditEntry` stores both, plus an `impersonated` flag, so
  `actions_by(log, agent)` lists exactly what the agent did.
- Starting impersonation requires a support ticket reference, logged as
  `impersonation_started`. Impersonating yourself is rejected.
- **Sensitive actions** (payout account, password, email, MFA) are refused
  in an impersonation session with `ImpersonationForbidden`. The refused
  attempt is itself logged, because that is exactly what an investigator
  needs to see. The seller can still change their own payout account.

## Trade-offs
- Blocking sensitive actions means support cannot fix a payout account even
  for a legitimate request; that should go through a separate, approved
  workflow with its own audit trail (and ideally the seller's confirmation).
- Some teams use read-only impersonation by default and require a second
  approver for write access. That is safer but slower for support.
- Tokens issued to an impersonation session should say so too (for example
  the `act` claim from RFC 8693 token exchange), so downstream services can
  log and restrict it the same way.
- Notifying the customer when staff access their account adds transparency
  and deters misuse, at the cost of some support friction.

## Run
```bash
python -m unittest -v test_solution.py
```
