"""Stop mass assignment: explicit input schemas per endpoint and per role.

The vulnerable handler copied every key of the JSON body onto the user
object (``for k, v in body.items(): setattr(user, k, v)``, or an ORM's
``user.update(**body)``). Any field on the model could be written by anyone
who could call the endpoint, including ``role``, ``email_verified``,
``credit_cents`` and ``org_id``.

The fix is an allowlist, not a blocklist:

* ``Schema`` declares exactly which fields an endpoint accepts, with types
  and limits. Unknown fields are rejected with 400 (or dropped and logged in
  ``strict=False`` mode), so a typo or an attack is visible.
* Privileged fields live in a different schema behind a different
  authorization check (``admin_update_user``).
* Responses go through an output allowlist, so internal fields such as the
  password hash are never serialised by accident.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Callable


# Unknown field names come from the attacker, so the lenient-mode log entry
# shows at most this many of them, each cut to this many characters.
MAX_LOGGED_UNKNOWN_FIELDS = 20
MAX_LOGGED_FIELD_NAME_LENGTH = 40


def describe_dropped_fields(schema_name: str, dropped: list[str]) -> str:
    """Build ONE bounded, single-line log entry for the dropped field names.

    ``repr()`` escapes newlines and control characters, so a key cannot
    forge a second log line; the caps stop a body with 50,000 junk keys
    from flooding the log.
    """
    shown = []
    for name in dropped[:MAX_LOGGED_UNKNOWN_FIELDS]:
        shown.append(repr(str(name)[:MAX_LOGGED_FIELD_NAME_LENGTH]))
    more = len(dropped) - len(shown)
    suffix = f", ... (+{more} more)" if more > 0 else ""
    return (f"{schema_name}: dropped {len(dropped)} unknown field(s): "
            f"{', '.join(shown)}{suffix}")


class ValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class Forbidden(PermissionError):
    pass


@dataclass(frozen=True)
class Field:
    type: type
    min_len: int = 0
    max_len: int | None = None
    choices: frozenset | None = None
    nullable: bool = False
    check: Callable[[Any], bool] | None = None


class Schema:
    def __init__(self, name: str, spec: dict[str, Field]):
        self.name, self.spec = name, spec

    def parse(self, body: Any, strict: bool = True, log: list | None = None) -> dict:
        """Validate ``body`` and return only declared fields."""
        if not isinstance(body, dict):
            raise ValidationError(["body must be a JSON object"])
        errors, out, dropped = [], {}, []
        for key, value in body.items():
            spec = self.spec.get(key)
            if spec is None:
                if strict:
                    errors.append(f"unknown field '{key}'")
                else:
                    dropped.append(key)
                continue
            err = self._check(key, value, spec)
            if err:
                errors.append(err)
            else:
                out[key] = value
        if errors:
            raise ValidationError(errors)
        if dropped and log is not None:
            log.append(describe_dropped_fields(self.name, dropped))
        return out

    @staticmethod
    def _check(key: str, value: Any, spec: Field) -> str | None:
        if value is None:
            return None if spec.nullable else f"'{key}' may not be null"
        # bool is a subclass of int in Python; do not accept True for an int.
        if type(value) is not spec.type:
            return f"'{key}' must be {spec.type.__name__}"
        if isinstance(value, str):
            if not spec.min_len <= len(value) <= (spec.max_len or len(value)):
                return f"'{key}' length must be {spec.min_len}..{spec.max_len}"
        if spec.choices is not None and value not in spec.choices:
            return f"'{key}' must be one of {sorted(spec.choices)}"
        if spec.check is not None and not spec.check(value):
            return f"'{key}' is invalid"
        return None


@dataclass
class User:
    id: int
    email: str
    display_name: str
    org_id: int
    role: str = "member"
    email_verified: bool = False
    credit_cents: int = 0
    password_hash: str = ""
    bio: str = ""
    timezone: str = "UTC"
    marketing_opt_in: bool = False


TIMEZONES = frozenset({"UTC", "Asia/Kolkata", "Europe/London", "America/New_York"})
ROLES = frozenset({"member", "billing", "admin"})

PROFILE_UPDATE = Schema("profile_update", {
    "display_name": Field(str, 1, 50, check=lambda s: s.strip() == s and s.isprintable()),
    "bio": Field(str, 0, 280),
    "timezone": Field(str, choices=TIMEZONES),
    "marketing_opt_in": Field(bool),
})

ADMIN_USER_UPDATE = Schema("admin_user_update", {
    "role": Field(str, choices=ROLES),
    "email_verified": Field(bool),
})

PUBLIC_FIELDS = ("id", "display_name", "bio", "timezone")
SELF_FIELDS = PUBLIC_FIELDS + ("email", "role", "email_verified", "marketing_opt_in")


def naive_update_profile(user: User, body: dict) -> User:
    """The vulnerable handler (kept for the tests)."""
    for key, value in body.items():
        if hasattr(user, key):
            setattr(user, key, value)
    return user


def _apply(user: User, data: dict, actor: User, audit: list) -> None:
    for key, value in data.items():
        old = getattr(user, key)
        if old != value:
            setattr(user, key, value)
            audit.append({"actor": actor.id, "user": user.id, "field": key})


def update_profile(actor: User, user: User, body: Any, audit: list) -> User:
    """``PATCH /users/{id}``: users may edit their own profile fields only."""
    if actor.id != user.id:
        raise Forbidden("can only edit your own profile")
    _apply(user, PROFILE_UPDATE.parse(body), actor, audit)
    return user


def admin_update_user(actor: User, user: User, body: Any, audit: list) -> User:
    """``PATCH /admin/users/{id}``: separate endpoint, separate permission."""
    if actor.role != "admin":
        raise Forbidden("admin only")
    if actor.org_id != user.org_id:
        raise Forbidden("user is in another organisation")
    data = ADMIN_USER_UPDATE.parse(body)
    if actor.id == user.id and data.get("role", actor.role) != actor.role:
        raise Forbidden("admins cannot change their own role")
    _apply(user, data, actor, audit)
    return user


def serialize(user: User, viewer: User) -> dict:
    """Output allowlist: what a viewer may see about ``user``."""
    allowed = SELF_FIELDS if viewer.id == user.id else PUBLIC_FIELDS
    return {f.name: getattr(user, f.name) for f in fields(user) if f.name in allowed}
