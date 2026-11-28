"""Check roles as exact set members, not as substrings of a string.

The admin API decided access with ``"admin" in user.roles``, where roles came
from the identity provider as one comma-separated string. ``in`` on a string
is a substring test, so "readonly-admin", "billing-admin-viewer" and even
"notadmin" all passed, and support staff with read-only roles could delete
customer accounts.

Fix: parse the claim into a set of exact, normalised role names once, reject
malformed claims, and check membership in that set.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

ROLE_SEPARATOR = ","
VALID_ROLE_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}")
ADMIN_ROLE = "admin"


class MalformedRoleClaim(ValueError):
    """The roles claim contained a value that is not a valid role name."""


@dataclass(frozen=True)
class User:
    name: str
    roles_claim: str          # e.g. "support,readonly-admin" from the IdP


def original_is_admin(user: User) -> bool:
    """Original check. BUG: substring test on the raw claim string."""
    return ADMIN_ROLE in user.roles_claim


def parse_roles(roles_claim: str) -> frozenset[str]:
    """Split the claim into exact role names.

    Whitespace around names is trimmed and names are lowercased because the
    IdP is inconsistent about both; empty entries ("a,,b") are skipped.
    Anything else that is not a plain role name is rejected, so a
    surprising claim fails closed instead of being guessed at.
    """
    roles = set()
    for raw_role in roles_claim.split(ROLE_SEPARATOR):
        role = raw_role.strip().lower()
        if role == "":
            continue
        if VALID_ROLE_NAME.fullmatch(role) is None:
            raise MalformedRoleClaim(f"invalid role name: {raw_role!r}")
        roles.add(role)
    return frozenset(roles)


def has_role(user: User, required_role: str) -> bool:
    """True only if ``required_role`` is exactly one of the user's roles."""
    try:
        roles = parse_roles(user.roles_claim)
    except MalformedRoleClaim:
        # WHY: a claim we cannot parse must never grant access.
        return False
    return required_role in roles


def is_admin(user: User) -> bool:
    """True only for users holding exactly the "admin" role."""
    return has_role(user, ADMIN_ROLE)


def delete_account(actor: User, account_id: str, deleted: list[str],
                   admin_check: Callable[[User], bool] = is_admin) -> int:
    """Admin endpoint: returns an HTTP status and records deletions."""
    if not admin_check(actor):
        return 403
    deleted.append(account_id)
    return 204
