"""Authorise object keys by whole path segments, not by string prefix.

A multi-tenant file service stores objects under keys like
"tenants/acme/invoices/7.pdf" and allowed a request if the key started with
the caller's prefix "tenants/acme". That string check also matches
"tenants/acme-labs/...", so any tenant whose name was a prefix of another's
could read the other tenant's files. This module splits keys into segments,
rejects ambiguous segments ("..", ".", empty), and checks that the first
segments are exactly the tenant's folder.
"""
from __future__ import annotations

TENANT_ROOT = "tenants"
# Keys longer than this are rejected before any parsing work.
MAX_KEY_LENGTH = 1024


class Forbidden(PermissionError):
    """Maps to HTTP 403."""


def naive_can_read(tenant: str, object_key: str) -> bool:
    """Original check: does the key start with the tenant's prefix string?"""
    return object_key.startswith(f"{TENANT_ROOT}/{tenant}")


def split_key(object_key: str) -> list[str]:
    """Split a key into segments, refusing anything that could mean two things.

    ".." and "." would let a key point somewhere other than where its prefix
    says; an empty segment ("a//b") is treated differently by different
    storage layers; a backslash is a separator on some of them.
    """
    if len(object_key) > MAX_KEY_LENGTH:
        raise Forbidden("key too long")
    if "\\" in object_key or "\x00" in object_key:
        raise Forbidden("illegal character in key")
    segments = object_key.split("/")
    for segment in segments:
        if segment in ("", ".", ".."):
            raise Forbidden(f"ambiguous key segment in {object_key!r}")
    return segments


def validate_tenant_name(tenant: str) -> None:
    """A tenant name must itself be exactly one plain segment."""
    if not tenant or "/" in tenant or tenant in (".", ".."):
        raise ValueError(f"invalid tenant name {tenant!r}")


def can_read(tenant: str, object_key: str) -> bool:
    """True only if the key lies inside tenants/<tenant>/ (segment by segment)."""
    validate_tenant_name(tenant)
    try:
        segments = split_key(object_key)
    except Forbidden:
        return False
    # Need at least root, tenant and one more segment: the tenant folder
    # itself is not a readable object.
    if len(segments) < 3:
        return False
    # Compare whole segments: "acme" must equal "acme", not just start "acme-labs".
    return segments[0] == TENANT_ROOT and segments[1] == tenant


def read_object(store: dict[str, bytes], tenant: str, object_key: str) -> bytes:
    """Return the object for the caller, or raise Forbidden / KeyError."""
    if not can_read(tenant, object_key):
        # Same error whether the object exists or not, so keys of other
        # tenants cannot be probed.
        raise Forbidden("not allowed")
    return store[object_key]
