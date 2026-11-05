"""Keep passwords and tokens out of application logs.

The original middleware logged every request object as-is, so login
passwords, ``Authorization: Bearer`` headers and ``?access_token=`` query
parameters were written to the logs and shipped to a third-party log service.
A first hot-fix deleted only a top-level ``password`` key and missed
everything else.

The fix has two layers: request logs are built from an allowlist of fields
(``safe_request_summary``), and a ``RedactingFilter`` on the log handler
scrubs secrets by key name and by value pattern from every record, including
exception tracebacks, as a safety net for ad-hoc log lines.
"""
from __future__ import annotations

import dataclasses
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"

# A key is sensitive if its normalised name contains one of these words.
# Matching on substrings catches "new_password", "X-Api-Key", "refreshToken".
SENSITIVE_KEY_WORDS = ("password", "passwd", "secret", "token", "authorization",
                       "apikey", "cookie", "session")

# Value patterns that are secrets wherever they appear in free text.
BEARER_PATTERN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
# Matches "name=value" both in query strings (?access_token=...) and in
# hand-written messages ("retrying with password=...").
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b((?:access_token|refresh_token|token|api_key|apikey|password|passwd|secret)=)"
    r"[^&\s\"',]+")

# Fields of a request that are safe to log. Everything else is dropped.
SAFE_HEADER_NAMES = ("user-agent", "content-type", "x-request-id")


@dataclass
class Request:
    """The parts of an HTTP request the logging middleware sees."""

    method: str
    url: str                                   # path plus query string
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, Any] = field(default_factory=dict)
    user_id: str | None = None


# --- original version ---------------------------------------------------
def log_request_naive(logger: logging.Logger, request: Request) -> None:
    """The bug: the whole request, headers and body included, goes into the log."""
    logger.info("request %s", request)


def log_request_hotfix(logger: logging.Logger, request: Request) -> None:
    """First fix: drop a top-level "password" key. Misses nested keys, other
    names, headers and query strings."""
    body = dict(request.body)
    body.pop("password", None)
    logger.info("request %s %s headers=%s body=%s", request.method, request.url,
                request.headers, body)


# --- fixed version: redaction helpers -------------------------------------
def is_sensitive_key(key: str) -> bool:
    """True if the key name looks like it holds a secret."""
    # WHY: normalise so "X-Api-Key", "api_key" and "apiKey" all become "xapikey"/"apikey".
    normalised = re.sub(r"[^a-z0-9]", "", key.lower())
    for word in SENSITIVE_KEY_WORDS:
        if word in normalised:
            return True
    return False


def redact_text(text: str) -> str:
    """Remove secrets that can be recognised by their shape in free text."""
    text = BEARER_PATTERN.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    return SECRET_ASSIGNMENT_PATTERN.sub(lambda m: f"{m.group(1)}{REDACTED}", text)


def redact_value(value: Any) -> Any:
    """Return a copy of ``value`` with sensitive dict keys and secret-shaped text redacted."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        # WHY: turn a dataclass (like Request) into a dict so its fields are
        # redacted by key name instead of being printed whole by repr().
        return redact_value(dataclasses.asdict(value))
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if is_sensitive_key(str(key)):
                cleaned[key] = REDACTED
            else:
                cleaned[key] = redact_value(item)
        return cleaned
    if isinstance(value, (list, tuple)):
        return type(value)(redact_value(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    # WHY: other objects end up in the log as their repr(), so redact that text
    # instead of passing the object through to be formatted later.
    return redact_text(repr(value))


def strip_query_secrets(url: str) -> str:
    """Keep the query string but replace values of sensitive parameters."""
    parts = urlsplit(url)
    params = []
    for name, val in parse_qsl(parts.query, keep_blank_values=True):
        params.append((name, REDACTED if is_sensitive_key(name) else val))
    return urlunsplit(parts._replace(query=urlencode(params, safe="[]")))


# --- fixed version: layer 1, allowlisted request summary -------------------
def safe_request_summary(request: Request) -> dict[str, Any]:
    """Only fields known to be safe. The body is never logged, only its key names."""
    headers = {}
    for name, val in request.headers.items():
        if name.lower() in SAFE_HEADER_NAMES:
            headers[name.lower()] = val
    return {
        "method": request.method,
        "url": strip_query_secrets(request.url),
        "user_id": request.user_id,
        "headers": headers,
        # WHY: key names help debugging ("which fields did the client send?")
        # without exposing any values.
        "body_keys": sorted(request.body),
    }


def log_request_safe(logger: logging.Logger, request: Request) -> None:
    """Log the allowlisted summary of a request."""
    logger.info("request %s", safe_request_summary(request))


# --- fixed version: layer 2, filter on the handler -------------------------
class RedactingFilter(logging.Filter):
    """Scrub secrets from every record before any handler formats it.

    Attach it to the *handler* (not a logger) so records from every logger,
    including third-party libraries that propagate to it, pass through it.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact message, arguments and traceback in place; never drop the record."""
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        if isinstance(record.args, dict):
            record.args = redact_value(record.args)
        elif record.args:
            record.args = tuple(redact_value(arg) for arg in record.args)
        if record.exc_info:
            # WHY: exception messages often include the failing value. Format
            # the traceback now and redact it; Formatter reuses exc_text.
            traceback_text = logging.Formatter().formatException(record.exc_info)
            record.exc_text = redact_text(traceback_text)
        return True
