"""The API's 500 responses contained the full Python traceback.

A debug-style error handler put ``traceback.format_exc()`` into the
response body. When the database was unreachable, the exception message
included the connection string, password and all, and the traceback showed
file paths, library versions and SQL. Anyone could trigger it by sending a
request that hit the failing code path. The fix returns a generic body with
a random error id to every client, keeps the details in the server-side log
under that id, and shows a message to the client only for errors the code
deliberately marks as safe to show.
"""
from __future__ import annotations

import secrets
import traceback
from dataclasses import dataclass
from typing import Callable

ERROR_ID_BYTES = 8
GENERIC_MESSAGE = "Internal error. Quote this id when contacting support."


@dataclass(frozen=True)
class Response:
    status: int
    body: dict[str, str]


class ClientError(Exception):
    """An error whose message was written for the client (HTTP 400).

    Only code we wrote raises this, with a message we chose, so it is safe to
    return. Every other exception may carry internal data.
    """


class ServerLog:
    """Stand-in for the service's private log sink."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, str]] = []      # (error id, details)

    def record(self, error_id: str, details: str) -> None:
        self.entries.append((error_id, details))


Handler = Callable[[], dict[str, str]]


# ---------------------------------------------------------------- sample app
def database_url() -> str:
    """Connection string as the app builds it from its config."""
    password = "-".join(["demo", "db", "pass"])        # built at runtime, not a real secret
    return f"postgresql://orders_app:{password}@db-primary.internal:5432/orders"


def get_order() -> dict[str, str]:
    """Handler whose database call fails; drivers often echo the DSN."""
    raise ConnectionError(f"could not connect to {database_url()}: timeout after 5s")


def create_order_with_bad_quantity() -> dict[str, str]:
    raise ClientError("quantity must be a positive integer")


# ---------------------------------------------------------------- original
def naive_handle(handler: Handler) -> Response:
    """Original middleware: send the traceback to whoever asked."""
    try:
        return Response(200, handler())
    except Exception:
        return Response(500, {"error": traceback.format_exc()})


# ---------------------------------------------------------------- the fix
def new_error_id() -> str:
    """Unguessable id that links a client report to a log entry."""
    return secrets.token_hex(ERROR_ID_BYTES)


def safe_handle(handler: Handler, log: ServerLog,
                make_error_id: Callable[[], str] = new_error_id) -> Response:
    """Run a handler; never put internal error details in the response."""
    try:
        return Response(200, handler())
    except ClientError as error:
        # The message was written for the client on purpose.
        return Response(400, {"error": str(error)})
    except Exception:
        error_id = make_error_id()
        # Full details stay server-side, findable by the id the client sees.
        log.record(error_id, traceback.format_exc())
        return Response(500, {"error": GENERIC_MESSAGE, "error_id": error_id})
