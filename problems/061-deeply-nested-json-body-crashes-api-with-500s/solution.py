"""Reject deeply nested JSON before parsing it, so one request cannot crash a handler.

A public "save draft" API parsed request bodies with ``json.loads`` and then
walked the result recursively to strip HTML from every string. A body of
100,000 ``[`` characters (100 KB, well under the 1 MB body limit) makes
``json.loads`` raise ``RecursionError``; a body nested 5,000 deep parses fine
but crashes the recursive walker. ``RecursionError`` is not a ``ValueError``,
so the handler's "bad JSON -> 400" branch never ran and every such request
became a 500 with a full stack trace. This module counts nesting depth with a
small iterative scanner before parsing and returns 400 above a fixed limit.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# Real draft documents are at most a few levels deep; 32 leaves a wide margin
# while staying far below Python's default recursion limit of 1000.
MAX_NESTING_DEPTH = 32
OPENING_BRACKETS = "[{"
CLOSING_BRACKETS = "]}"


@dataclass
class Response:
    """Minimal HTTP response: status code and a short body."""
    status: int
    body: str


class TooDeeplyNested(ValueError):
    """The JSON body nests arrays/objects deeper than we accept."""


def strip_html(value: Any) -> Any:
    """Recursively remove '<' and '>' from every string (the app's sanitiser)."""
    if isinstance(value, str):
        return value.replace("<", "").replace(">", "")
    if isinstance(value, list):
        return [strip_html(item) for item in value]
    if isinstance(value, dict):
        return {key: strip_html(item) for key, item in value.items()}
    return value


def naive_handle_save_draft(body: str) -> Response:
    """Original handler: only JSONDecodeError was treated as a client error."""
    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return Response(400, "invalid JSON")
    # Any other exception escapes to the framework, which turns it into a 500.
    cleaned = strip_html(document)
    return Response(200, json.dumps(cleaned)[:50])


def max_nesting_depth(body: str, limit: int) -> int:
    """Return the deepest bracket nesting in ``body``, stopping early past ``limit``.

    The scan is a plain loop (no recursion), so it cannot itself overflow the
    stack. Brackets inside strings do not count, so we track whether we are
    inside a string and skip the character after a backslash.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for character in body:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in OPENING_BRACKETS:
            depth += 1
            deepest = max(deepest, depth)
            # Stop as soon as we know the answer, so a 1 MB attack body is
            # rejected after reading only a few dozen characters.
            if deepest > limit:
                return deepest
        elif character in CLOSING_BRACKETS:
            depth -= 1
    return deepest


def parse_limited_json(body: str, limit: int = MAX_NESTING_DEPTH) -> Any:
    """Parse JSON only if its nesting depth is within ``limit``."""
    if max_nesting_depth(body, limit) > limit:
        raise TooDeeplyNested(f"JSON nesting deeper than {limit} levels")
    return json.loads(body)


def handle_save_draft(body: str) -> Response:
    """Fixed handler: depth is checked first, every parse failure is a 400."""
    try:
        document = parse_limited_json(body)
    except TooDeeplyNested:
        return Response(400, "JSON nested too deeply")
    except ValueError:
        # JSONDecodeError and UnicodeDecodeError are both ValueError subclasses.
        return Response(400, "invalid JSON")
    # Safe now: the walker recurses at most MAX_NESTING_DEPTH levels.
    cleaned = strip_html(document)
    return Response(200, json.dumps(cleaned)[:50])
