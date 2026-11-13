"""Access tokens whose role claim stops working the moment the role changes.

An admin console issued signed access tokens valid for 12 hours that carried
the user's role ("admin"). Authorization trusted that claim. When a contractor
was demoted to "viewer" (and later offboarded), their existing token kept full
admin rights until it expired, and they deleted a customer's data hours after
losing access. This version stamps every token with the user's permission
version; any role change bumps the version, and authorization checks it (and
the current role) against the user store on every request.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass, field

TOKEN_LIFETIME_SECONDS = 12 * 60 * 60
ROLE_PERMISSIONS = {
    "admin": {"read", "delete_customer"},
    "viewer": {"read"},
}


class AccessDenied(Exception):
    """Raised when a request is not allowed, with the reason for the audit log."""


@dataclass
class UserRecord:
    role: str
    # Bumped on every role change or deactivation; old tokens carry the old number.
    permission_version: int = 1
    active: bool = True


@dataclass
class UserStore:
    users: dict[str, UserRecord] = field(default_factory=dict)

    def change_role(self, user_id: str, new_role: str) -> None:
        record = self.users[user_id]
        record.role = new_role
        record.permission_version += 1

    def deactivate(self, user_id: str) -> None:
        record = self.users[user_id]
        record.active = False
        record.permission_version += 1


def _encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(secret: bytes, store: UserStore, user_id: str, now: float) -> str:
    """Sign the user's current role and permission version into a token."""
    record = store.users[user_id]
    claims = {
        "sub": user_id,
        "role": record.role,
        "pv": record.permission_version,
        "exp": now + TOKEN_LIFETIME_SECONDS,
    }
    payload = _encode(json.dumps(claims, sort_keys=True).encode("utf-8"))
    signature = _encode(hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def verify_token(secret: bytes, token: str, now: float) -> dict:
    """Check signature and expiry; return the claims. Does NOT check the role is still current."""
    payload, _, signature = token.partition(".")
    expected = _encode(hmac.new(secret, payload.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        raise AccessDenied("bad signature")
    claims = json.loads(_decode(payload))
    if now >= claims["exp"]:
        raise AccessDenied("token expired")
    return claims


def naive_authorize(secret: bytes, token: str, permission: str, now: float) -> None:
    """Original check: trust the role written into the token for its whole lifetime."""
    claims = verify_token(secret, token, now)
    if permission not in ROLE_PERMISSIONS.get(claims["role"], set()):
        raise AccessDenied(f"role {claims['role']} lacks {permission}")


def authorize(secret: bytes, store: UserStore, token: str, permission: str, now: float) -> None:
    """Allow the request only if the token's permissions are still the user's permissions.

    The version check makes every token issued before a role change useless
    at once, without a token blocklist. Permissions come from the store's
    current role, never from the token, so a stale claim cannot grant anything.
    """
    claims = verify_token(secret, token, now)
    record = store.users.get(claims["sub"])
    if record is None or not record.active:
        raise AccessDenied("user is not active")
    if claims["pv"] != record.permission_version:
        raise AccessDenied("permissions changed since token was issued; sign in again")
    if permission not in ROLE_PERMISSIONS.get(record.role, set()):
        raise AccessDenied(f"role {record.role} lacks {permission}")
