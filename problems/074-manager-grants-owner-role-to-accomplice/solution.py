"""Stop workspace managers from handing out roles more powerful than their own.

The original role-change endpoint only asked "may this user change roles?".
Managers have that permission so they can onboard their team, but nothing
limited WHICH role they could hand out: a manager invited an accomplice as
owner (who can export data and delete the workspace) and even promoted
himself.

The fix checks delegation, not just the action: a user may only grant or
remove a role whose permissions are a subset of their own, may not change
their own role, and the last owner of a workspace cannot be demoted.
"""
from __future__ import annotations

from dataclasses import dataclass, field

CHANGE_ROLES = "members:change_role"
OWNER = "owner"

# Each role is just a set of permissions. Comparing sets (not a numeric rank)
# also works for custom roles that are not strictly above or below others.
ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({"docs:read"}),
    "member": frozenset({"docs:read", "docs:write"}),
    "manager": frozenset({"docs:read", "docs:write", CHANGE_ROLES}),
    "billing_admin": frozenset({"docs:read", "billing:refund"}),
    OWNER: frozenset({"docs:read", "docs:write", CHANGE_ROLES, "billing:refund",
                      "workspace:export", "workspace:delete"}),
}


class RoleChangeDenied(Exception):
    """The actor may not make this role change."""


@dataclass
class Workspace:
    """Who holds which role in one workspace."""
    roles: dict[str, str] = field(default_factory=dict)   # user_id -> role name

    def permissions_of(self, user_id: str) -> frozenset[str]:
        """Permissions of a member; non-members have none."""
        role = self.roles.get(user_id)
        if role is None:
            return frozenset()
        return ROLE_PERMISSIONS[role]

    def owner_count(self) -> int:
        """How many owners the workspace has."""
        count = 0
        for role in self.roles.values():
            if role == OWNER:
                count += 1
        return count


# --- the original check --------------------------------------------------------
def naive_assign_role(workspace: Workspace, actor: str, target: str, new_role: str) -> None:
    """The bug: having CHANGE_ROLES lets you hand out ANY role, to anyone, even yourself."""
    if CHANGE_ROLES not in workspace.permissions_of(actor):
        raise RoleChangeDenied("not allowed to change roles")
    workspace.roles[target] = new_role


# --- the fix -------------------------------------------------------------------
def can_delegate(actor_permissions: frozenset[str], role: str) -> bool:
    """True if every permission of ``role`` is one the actor already has."""
    return ROLE_PERMISSIONS[role] <= actor_permissions


def assign_role(workspace: Workspace, actor: str, target: str, new_role: str) -> None:
    """Change (or grant) ``target``'s role, enforcing delegation limits."""
    if new_role not in ROLE_PERMISSIONS:
        raise RoleChangeDenied(f"unknown role {new_role!r}")
    actor_permissions = workspace.permissions_of(actor)
    if CHANGE_ROLES not in actor_permissions:
        raise RoleChangeDenied("not allowed to change roles")
    # Self-service role changes are how a compromised manager account becomes
    # an owner; another owner must do it.
    if actor == target:
        raise RoleChangeDenied("cannot change your own role")
    if not can_delegate(actor_permissions, new_role):
        raise RoleChangeDenied(f"cannot grant {new_role!r}: it has permissions you lack")
    _check_current_role_removable(workspace, actor_permissions, target)
    workspace.roles[target] = new_role


def _check_current_role_removable(workspace: Workspace, actor_permissions: frozenset[str],
                                  target: str) -> None:
    """Refuse to change someone who holds more power than the actor.

    WHY: otherwise a manager could demote the owners and leave himself as the
    most powerful member, which is an escalation by subtraction.
    """
    current_role = workspace.roles.get(target)
    if current_role is None:
        return
    if not can_delegate(actor_permissions, current_role):
        raise RoleChangeDenied(f"cannot change a {current_role!r}: it has permissions you lack")
    # A workspace with no owner cannot be administered or recovered.
    if current_role == OWNER and workspace.owner_count() == 1:
        raise RoleChangeDenied("cannot demote the last owner")


def remove_member(workspace: Workspace, actor: str, target: str) -> None:
    """Remove a member, with the same limits as changing their role."""
    actor_permissions = workspace.permissions_of(actor)
    if CHANGE_ROLES not in actor_permissions:
        raise RoleChangeDenied("not allowed to remove members")
    if target not in workspace.roles:
        raise RoleChangeDenied("not a member")
    _check_current_role_removable(workspace, actor_permissions, target)
    del workspace.roles[target]
