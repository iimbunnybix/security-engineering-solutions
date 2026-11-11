"""Gateway and backend disagreeing on duplicate JSON keys let users sign up as admin.

The API gateway checked that a self-service signup asked for role "user", then
forwarded the raw body to the account service. The gateway's parser kept the
FIRST value of a repeated key, while the backend's json.loads keeps the LAST,
so {"role": "user", "role": "admin"} passed the check and created an admin.
The fix parses once with a hook that rejects duplicate keys at every nesting
level, and forwards the exact object that was validated, re-serialised.
"""
from __future__ import annotations

import json
from typing import Any

SELF_SERVICE_ROLE = "user"
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_FORBIDDEN = 403


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


def first_key_wins(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object keeping the first value of a repeated key (like the gateway's parser)."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key not in result:
            result[key] = value
    return result


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object, refusing any repeated key.

    json calls this hook for every object, nested ones included, after
    unescaping, so "role" and "\\u0072ole" are caught as the same key.
    """
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate key {key!r}")
        result[key] = value
    return result


def strict_loads(body: str) -> Any:
    """Parse JSON that must not contain repeated keys anywhere."""
    return json.loads(body, object_pairs_hook=reject_duplicate_keys)


class AccountService:
    """The backend: parses with plain json.loads, where the last duplicate wins."""

    def __init__(self) -> None:
        self.accounts: dict[str, str] = {}

    def create_account(self, body: str) -> tuple[int, dict]:
        """Create an account from the forwarded JSON body. Trusts the gateway's check."""
        data = json.loads(body)
        self.accounts[data["email"]] = data["role"]
        return HTTP_CREATED, {"email": data["email"], "role": data["role"]}


def validate_signup(data: Any) -> str | None:
    """Return an error message, or None if this is an allowed self-service signup."""
    if not isinstance(data, dict):
        return "body must be a JSON object"
    if not isinstance(data.get("email"), str) or "@" not in data["email"]:
        return "email is required"
    if data.get("role") != SELF_SERVICE_ROLE:
        return "self-service signup can only create role 'user'"
    return None


def naive_gateway_signup(body: str, backend: AccountService) -> tuple[int, dict]:
    """Original gateway: checks its own parse, then forwards the raw body."""
    data = json.loads(body, object_pairs_hook=first_key_wins)
    error = validate_signup(data)
    if error:
        return HTTP_FORBIDDEN, {"error": error}
    # The backend re-parses these bytes with different duplicate-key rules.
    return backend.create_account(body)


def gateway_signup(body: str, backend: AccountService) -> tuple[int, dict]:
    """Fixed gateway: strict parse, validate, forward what was validated."""
    try:
        data = strict_loads(body)
    except DuplicateKeyError as error:
        return HTTP_BAD_REQUEST, {"error": str(error)}
    except json.JSONDecodeError:
        return HTTP_BAD_REQUEST, {"error": "body is not valid JSON"}
    error = validate_signup(data)
    if error:
        return HTTP_FORBIDDEN, {"error": error}
    # Re-serialising guarantees the backend cannot read anything other than
    # the object we just checked, whatever its parser does with odd input.
    return backend.create_account(json.dumps(data))
