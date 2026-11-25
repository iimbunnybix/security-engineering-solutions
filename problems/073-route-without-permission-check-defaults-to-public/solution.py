"""Stop new API routes from being public just because nobody added a permission.

The original router only checked a permission when the route declared one.
A developer added ``GET /api/reports/customers.csv`` and forgot the
``permission=`` argument, so the route silently became reachable by anyone,
including anonymous visitors, and leaked the full customer list.

The fix makes the router deny by default: every route must declare its
access rule when it is registered (a permission, or an explicit PUBLIC
marker), registration fails loudly otherwise, and a startup audit lists
every route with its rule so reviewers can see what is public.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# Explicit marker for routes that really are meant for anonymous visitors.
PUBLIC = "public"
# Any logged-in user, no extra permission (for example "my profile").
AUTHENTICATED = "authenticated"

STATUS_OK = 200
STATUS_UNAUTHENTICATED = 401
STATUS_FORBIDDEN = 403
STATUS_NOT_FOUND = 404


@dataclass(frozen=True)
class User:
    """The caller; None is used for anonymous requests."""
    user_id: str
    permissions: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Response:
    status: int
    body: str


Handler = Callable[[User | None], str]


class RouteConfigError(Exception):
    """A route was registered without a valid access rule."""


# --- the original, default-allow router --------------------------------------
class NaiveRouter:
    """The bug: a route with no permission is open to everyone."""

    def __init__(self) -> None:
        self._routes: dict[str, tuple[Handler, str | None]] = {}

    def add(self, path: str, handler: Handler, permission: str | None = None) -> None:
        """Register a route; forgetting ``permission`` is accepted silently."""
        self._routes[path] = (handler, permission)

    def dispatch(self, path: str, user: User | None) -> Response:
        """Run the handler, checking a permission only if one was declared."""
        if path not in self._routes:
            return Response(STATUS_NOT_FOUND, "not found")
        handler, permission = self._routes[path]
        if permission is not None:
            if user is None:
                return Response(STATUS_UNAUTHENTICATED, "login required")
            if permission not in user.permissions:
                return Response(STATUS_FORBIDDEN, "forbidden")
        return Response(STATUS_OK, handler(user))


# --- the fix -------------------------------------------------------------------
@dataclass
class SecureRouter:
    """Deny by default: no route is reachable without a declared access rule."""
    _routes: dict[str, tuple[Handler, str]] = field(default_factory=dict)

    def add(self, path: str, handler: Handler, access: str) -> None:
        """Register a route. ``access`` is required and must be non-empty.

        WHY a required argument with no default: the safe choice must not be
        something a developer has to remember to type.
        """
        if not isinstance(access, str) or not access.strip():
            raise RouteConfigError(f"route {path!r} has no access rule")
        if path in self._routes:
            # A second registration could quietly replace a protected route.
            raise RouteConfigError(f"route {path!r} registered twice")
        self._routes[path] = (handler, access)

    def dispatch(self, path: str, user: User | None) -> Response:
        """Run the handler only if the caller satisfies the route's rule."""
        if path not in self._routes:
            return Response(STATUS_NOT_FOUND, "not found")
        handler, access = self._routes[path]
        denial = check_access(access, user)
        if denial is not None:
            return denial
        return Response(STATUS_OK, handler(user))

    def audit(self) -> list[tuple[str, str]]:
        """Return (path, access rule) for every route, sorted by path.

        Printed at startup and diffed in code review, this makes a new PUBLIC
        route visible instead of hidden in a missing argument.
        """
        return sorted((path, access) for path, (_handler, access) in self._routes.items())

    def public_paths(self) -> list[str]:
        """Paths anonymous visitors can reach; compared against an approved list in CI."""
        return [path for path, access in self.audit() if access == PUBLIC]


def check_access(access: str, user: User | None) -> Response | None:
    """Return a denial response, or None when the caller may proceed."""
    if access == PUBLIC:
        return None
    if user is None:
        return Response(STATUS_UNAUTHENTICATED, "login required")
    if access == AUTHENTICATED:
        return None
    if access not in user.permissions:
        return Response(STATUS_FORBIDDEN, "forbidden")
    return None


def unapproved_public_routes(router: SecureRouter, approved: set[str]) -> list[str]:
    """CI check: public routes that nobody has signed off on."""
    unapproved = []
    for path in router.public_paths():
        if path not in approved:
            unapproved.append(path)
    return unapproved
