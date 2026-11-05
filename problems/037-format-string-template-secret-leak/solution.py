"""Render tenant-written notification templates without leaking server secrets.

Tenant admins write their own order-notification templates, e.g.
``"Hi {customer.name}, order {order.id} has shipped"``. The original code
rendered them with ``str.format(customer=..., order=...)``. ``str.format`` can
follow attributes and indexes, so a template such as
``"{order.__init__.__globals__[WEBHOOK_SIGNING_KEY]}"`` walks from the order
object to this module's globals and prints a server secret into the email.

``render_template`` parses the template itself and only substitutes
placeholders from a fixed allow-list of plain values. Attribute access,
indexing, conversions (``!r``) and format specs (``:>999999999``) are rejected,
so the template can no longer reach anything we did not choose to expose.
"""
from __future__ import annotations

import secrets
from string import Formatter

# A per-process fake secret, built at runtime so no real-looking key is in the file.
WEBHOOK_SIGNING_KEY = "demo-signing-key-" + secrets.token_hex(8)

# The only placeholders a tenant template may use.
ALLOWED_PLACEHOLDERS = (
    "customer.name",
    "customer.email",
    "order.id",
    "order.total",
)
MAX_TEMPLATE_LENGTH = 2000


class TemplateError(ValueError):
    """Raised when a tenant template uses something outside the allow-list."""


class Customer:
    """A customer record as the notification service sees it."""

    def __init__(self, name: str, email: str) -> None:
        self.name = name
        self.email = email


class Order:
    """An order record as the notification service sees it."""

    def __init__(self, order_id: str, total: str) -> None:
        self.id = order_id
        self.total = total


def naive_render_template(template: str, customer: Customer, order: Order) -> str:
    """Original version: hand real objects to ``str.format``.

    Any attribute chain the template names is followed, including dunder
    attributes that lead to module globals.
    """
    return template.format(customer=customer, order=order)


def build_context(customer: Customer, order: Order) -> dict[str, str]:
    """Copy the allowed fields into plain strings.

    The template only ever sees these strings, never the objects, so there is
    no attribute chain left to walk.
    """
    return {
        "customer.name": str(customer.name),
        "customer.email": str(customer.email),
        "order.id": str(order.id),
        "order.total": str(order.total),
    }


def check_placeholder(field_name: str, conversion: str | None, format_spec: str) -> None:
    """Reject any placeholder that is not exactly one allow-listed name."""
    if field_name not in ALLOWED_PLACEHOLDERS:
        raise TemplateError(f"unknown placeholder {{{field_name}}}")
    if conversion is not None:
        # !r / !s / !a are not needed for notifications and widen the surface.
        raise TemplateError(f"conversion !{conversion} is not allowed")
    if format_spec:
        # A spec like ':>999999999' would allocate ~1 GB per render.
        raise TemplateError("format specs are not allowed")


def render_template(template: str, customer: Customer, order: Order) -> str:
    """Render ``template`` using only allow-listed plain values.

    Raises ``TemplateError`` for anything else, so a bad template is caught
    when the tenant saves it instead of leaking data when it is sent.
    """
    if len(template) > MAX_TEMPLATE_LENGTH:
        raise TemplateError("template is too long")
    context = build_context(customer, order)
    pieces: list[str] = []
    try:
        parsed = list(Formatter().parse(template))
    except ValueError as error:          # e.g. an unmatched "{"
        raise TemplateError(str(error)) from error
    for literal_text, field_name, format_spec, conversion in parsed:
        pieces.append(literal_text)
        if field_name is None:
            continue                     # trailing literal text, no placeholder
        check_placeholder(field_name, conversion, format_spec or "")
        pieces.append(context[field_name])
    return "".join(pieces)
