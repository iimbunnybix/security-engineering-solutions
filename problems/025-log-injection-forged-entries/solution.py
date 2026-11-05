"""Stop attackers from forging lines in the authentication log.

The login service wrote ``f"{time} WARN login failed user={username}"`` to a
plain-text log that the security team's alerting and investigations rely on.
A username is attacker-controlled. Sending a username containing a newline
followed by a fake "login succeeded user=admin" line created a forged entry
that looked exactly like a real one, and a flood of failures could be hidden
behind fake successes.

The fix never writes untrusted text raw: every value is escaped so that line
breaks and other control characters become visible escape sequences
(``\\n``), values are always quoted, and so one call always produces exactly
one log line.
"""
from __future__ import annotations

import unicodedata
from typing import Callable

Clock = Callable[[], str]

# Characters that end a line in common log viewers and parsers, beyond "\n".
# U+0085 (NEL), U+2028 and U+2029 are line breaks for many Unicode-aware tools.
EXTRA_LINE_BREAKS = {"\u0085": "\\u0085", " ": "\\u2028", " ": "\\u2029"}
SIMPLE_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}
MAX_VALUE_LENGTH = 200


def naive_log_line(timestamp: str, level: str, event: str, username: str) -> str:
    """The original format: untrusted username pasted in as-is."""
    return f"{timestamp} {level} {event} user={username}"


def escape_char(char: str) -> str:
    """Escape one character if it could break or fake the log format."""
    if char in SIMPLE_ESCAPES:
        return SIMPLE_ESCAPES[char]
    if char in EXTRA_LINE_BREAKS:
        return EXTRA_LINE_BREAKS[char]
    # Category "Cc" is every other control character (ESC for terminal
    # colour codes, NUL, backspace...). Show its code point instead.
    if unicodedata.category(char) == "Cc":
        return f"\\x{ord(char):02x}"
    return char


def escape_value(value: str) -> str:
    """Quote and escape an untrusted value so it stays on one line."""
    if len(value) > MAX_VALUE_LENGTH:
        value = value[:MAX_VALUE_LENGTH] + "...(truncated)"
    escaped = "".join(escape_char(char) for char in value)
    return f'"{escaped}"'


def safe_log_line(timestamp: str, level: str, event: str, fields: dict[str, str]) -> str:
    """One log line: trusted prefix, then key="escaped value" pairs."""
    parts = [timestamp, level, event]
    for key in sorted(fields):
        parts.append(f"{key}={escape_value(fields[key])}")
    return " ".join(parts)


class AuthLog:
    """Append-only text log of login events (an in-memory file for tests)."""

    def __init__(self, clock: Clock, escape: bool = True) -> None:
        self.clock = clock
        self.escape = escape
        self.text = ""

    def login_failed(self, username: str) -> None:
        """Record a failed login attempt for ``username``."""
        timestamp = self.clock()
        if self.escape:
            line = safe_log_line(timestamp, "WARN", "login_failed", {"user": username})
        else:
            line = naive_log_line(timestamp, "WARN", "login_failed", username)
        self.text += line + "\n"

    def lines(self) -> list[str]:
        """Split the log the way log shippers do: one entry per line."""
        return self.text.splitlines()
