"""Context-aware auto-escaping templates to stop stored XSS.

The support console built HTML with f-strings, inserting customer-controlled
values (display name, ticket subject, website URL) directly into the page.
A display name such as ``<img src=x onerror=...>`` ran JavaScript in every
support agent's browser that opened the ticket.

``Template`` escapes every placeholder by default and picks the encoding
from the placeholder's context filter:

``{{ v }}``        HTML text and quoted attribute values (``html.escape``)
``{{ v|url }}``    ``href``/``src`` values: only http, https, mailto and
                   relative URLs survive; anything else becomes ``#``
``{{ v|js }}``     data inside ``<script>``: JSON with ``<``, ``>``, ``&`` and
                   U+2028/2029 escaped, so ``</script>`` cannot close the tag
``{{ v|safe }}``   only accepted for ``SafeHTML`` objects produced by code,
                   never for raw strings

``csp_header`` builds a nonce-based Content-Security-Policy as a second layer:
even if an escaping bug slips through, injected inline scripts do not run.
"""
from __future__ import annotations

import html
import json
import re
import secrets
from typing import Any
from urllib.parse import urlsplit

_PLACEHOLDER = re.compile(r"\{\{\s*(\w+)\s*(?:\|\s*(\w+)\s*)?\}\}")
_ALLOWED_SCHEMES = {"http", "https", "mailto"}
# Browsers ignore ASCII tab/newline and leading control/space characters in
# URLs, so "java\tscript:" and " javascript:" are still javascript: URLs.
_URL_STRIP = re.compile(r"[\x00-\x20\x7f]")


class SafeHTML(str):
    """Markup produced by trusted code (for example another rendered Template)."""


def escape_html(value: Any) -> str:
    return html.escape(str(value), quote=True)


def sanitize_url(value: Any) -> str:
    """Return the URL if its scheme is allowed, else ``#``."""
    raw = str(value)
    cleaned = _URL_STRIP.sub("", raw)
    if not cleaned:
        return "#"
    if cleaned.startswith("//") or cleaned.startswith("\\"):
        return "#"                       # protocol-relative: other origin
    scheme = urlsplit(cleaned).scheme.lower()
    if scheme and scheme not in _ALLOWED_SCHEMES:
        return "#"
    if not scheme and ":" in cleaned.split("/", 1)[0]:
        return "#"                       # e.g. "javascript&colon;" variants
    return raw.strip()


def js_literal(value: Any) -> str:
    """JSON that is safe to place inside an HTML ``<script>`` element."""
    text = json.dumps(value, ensure_ascii=False)
    return (text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


class Template:
    """Tiny auto-escaping template. Unknown filters are errors, not no-ops."""

    def __init__(self, source: str):
        self.source = source
        for m in _PLACEHOLDER.finditer(source):
            if m.group(2) not in (None, "url", "js", "safe"):
                raise ValueError(f"unknown filter {m.group(2)!r}")

    def render(self, **ctx: Any) -> SafeHTML:
        def sub(m: re.Match) -> str:
            name, flt = m.group(1), m.group(2)
            if name not in ctx:
                raise KeyError(f"missing template value {name!r}")
            value = ctx[name]
            if flt == "url":
                return escape_html(sanitize_url(value))
            if flt == "js":
                return js_literal(value)
            if flt == "safe":
                if not isinstance(value, SafeHTML):
                    raise TypeError(f"{name!r}: |safe needs SafeHTML, got {type(value).__name__}")
                return value
            return escape_html(value)
        return SafeHTML(_PLACEHOLDER.sub(sub, self.source))


def new_nonce() -> str:
    return secrets.token_urlsafe(16)


def csp_header(nonce: str) -> str:
    return ("default-src 'self'; "
            f"script-src 'nonce-{nonce}' 'strict-dynamic'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'")


TICKET_ROW = Template(
    '<tr data-ticket="{{ ticket_id }}">'
    '<td class="name">{{ display_name }}</td>'
    '<td class="subject" title="{{ subject }}">{{ subject }}</td>'
    '<td><a href="{{ website|url }}" rel="noopener noreferrer">site</a></td>'
    '</tr>')

TICKET_PAGE = Template(
    "<html><body><table>{{ rows|safe }}</table>"
    '<script nonce="{{ nonce }}">window.TICKET = {{ ticket|js }};</script>'
    "</body></html>")


def naive_ticket_row(t: dict) -> str:
    """The vulnerable version (kept for the tests)."""
    return (f'<tr data-ticket="{t["ticket_id"]}"><td class="name">{t["display_name"]}</td>'
            f'<td class="subject" title="{t["subject"]}">{t["subject"]}</td>'
            f'<td><a href="{t["website"]}">site</a></td></tr>')


def render_ticket_page(ticket: dict, nonce: str) -> SafeHTML:
    rows = TICKET_ROW.render(**ticket)
    return TICKET_PAGE.render(rows=rows, nonce=nonce, ticket=ticket)
