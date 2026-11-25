# 074 · A workspace manager made his accomplice an owner, who then exported and deleted the workspace

## Problem
A project-management SaaS lets each customer workspace have owners,
managers, members, viewers and a custom "billing admin" role. Managers can
change roles so they can onboard their own teams without bothering the
owner. A manager who was leaving the company on bad terms invited a personal
email address with the role `owner`. That account exported every document,
issued refunds to a card it controlled, and then deleted the workspace. The
real owner found out from the "workspace deleted" email. Restoring from
backups took the customer's team offline for most of a day.

## Root cause
The role-change endpoint checked **the action, not the delegation**:

```python
if "members:change_role" not in permissions_of(actor):
    raise RoleChangeDenied
roles[target] = new_role          # any role, any target, including yourself
```

Having permission to change roles let a manager grant any role at all,
including ones with permissions he did not have himself (`owner`,
`billing_admin`), promote himself, or demote the real owner. The tests in
`ReproduceProblem` show all three with `naive_assign_role`, including a
workspace left with zero owners.

## Solution
`assign_role` in `solution.py` adds delegation rules on top of the
permission check:

1. **You can only grant what you have.** The new role's permission set must
   be a subset of the actor's. Sets are compared instead of a numeric rank,
   so a sideways custom role (`billing_admin` can refund, a manager cannot)
   is also refused.
2. **You can only change someone who has no more than you.** Otherwise a
   manager could demote the owners and become the most powerful member by
   subtraction. `remove_member` uses the same rule.
3. **No self-service role changes.** A compromised manager account cannot
   promote itself; another owner has to.
4. **The last owner cannot be demoted or removed**, so a workspace always
   has someone who can administer and recover it.

A manager can still invite members and promote a colleague to manager,
which is what the permission was for.

## Trade-offs
- Subset checks require roles to be defined as permission sets. Systems
  with role inheritance or conditions (ABAC) need the same idea expressed as
  "the actor must satisfy every grant they hand out".
- Some teams want managers to *request* higher roles; add an approval flow
  for owners instead of loosening the rule.
- These rules stop escalation through the role API only. Sensitive actions
  (export, delete, refunds) should also notify owners and, for deletion,
  have a delay or undo window, so a single compromised account cannot do
  irreversible damage in minutes.
- Role changes should be written to the audit log (see 008) with the actor,
  target, old and new role.

## Run
```bash
python -m unittest -v test_solution.py
```
