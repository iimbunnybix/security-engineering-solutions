"""Checkout that recomputes prices and validates quantities on the server.

The original checkout API trusted the cart the browser sent: each line carried
its own unit price and quantity, and the server just multiplied and summed.
Shoppers edited the request to send a negative quantity (or a price of 0.01),
which produced orders with tiny or negative totals; negative totals were
credited to the shopper's store wallet. This version ignores client prices,
looks every price up in the server-side catalog, accepts only whole-number
quantities in a sane range, uses Decimal money, and refuses negative totals.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

MIN_QUANTITY = 1
MAX_QUANTITY_PER_LINE = 20
CENT = Decimal("0.01")


class InvalidCart(ValueError):
    """Raised when a submitted cart cannot be priced safely."""


@dataclass(frozen=True)
class PricedLine:
    sku: str
    quantity: int
    unit_price: Decimal

    @property
    def line_total(self) -> Decimal:
        return self.unit_price * self.quantity


def naive_checkout_total(cart_lines: list[dict]) -> float:
    """Original version: multiplies whatever price and quantity the client sent."""
    total = 0.0
    for line in cart_lines:
        total += float(line["unit_price"]) * float(line["quantity"])
    return round(total, 2)


def parse_quantity(raw_quantity: object) -> int:
    """Accept only a real integer between MIN_QUANTITY and MAX_QUANTITY_PER_LINE.

    bool is a subclass of int in Python (True == 1), so it is rejected
    explicitly; floats and strings are rejected so "1.5" or "-0" cannot sneak in.
    """
    if isinstance(raw_quantity, bool) or not isinstance(raw_quantity, int):
        raise InvalidCart(f"quantity must be a whole number, got {raw_quantity!r}")
    if raw_quantity < MIN_QUANTITY or raw_quantity > MAX_QUANTITY_PER_LINE:
        raise InvalidCart(
            f"quantity must be between {MIN_QUANTITY} and {MAX_QUANTITY_PER_LINE}")
    return raw_quantity


def price_line(line: dict, catalog: dict[str, Decimal]) -> PricedLine:
    """Turn one client line into a priced line using only the server catalog.

    Any "unit_price" the client sent is ignored on purpose: the browser is
    under the attacker's control, so prices must come from our own data.
    """
    sku = line.get("sku")
    if not isinstance(sku, str) or sku not in catalog:
        raise InvalidCart(f"unknown product {sku!r}")
    quantity = parse_quantity(line.get("quantity"))
    return PricedLine(sku=sku, quantity=quantity, unit_price=catalog[sku])


def merge_duplicate_skus(priced_lines: list[PricedLine]) -> dict[str, int]:
    """Sum quantities per SKU so the per-line limit cannot be dodged by repeating a SKU."""
    quantity_by_sku: dict[str, int] = {}
    for line in priced_lines:
        quantity_by_sku[line.sku] = quantity_by_sku.get(line.sku, 0) + line.quantity
    for sku, quantity in quantity_by_sku.items():
        if quantity > MAX_QUANTITY_PER_LINE:
            raise InvalidCart(f"at most {MAX_QUANTITY_PER_LINE} of {sku} per order")
    return quantity_by_sku


def checkout_total(cart_lines: list[dict], catalog: dict[str, Decimal]) -> Decimal:
    """Price the cart on the server and return a non-negative total in cents precision."""
    if not cart_lines:
        raise InvalidCart("cart is empty")
    priced_lines = [price_line(line, catalog) for line in cart_lines]
    quantity_by_sku = merge_duplicate_skus(priced_lines)
    total = Decimal("0")
    for sku, quantity in quantity_by_sku.items():
        total += catalog[sku] * quantity
    # Defence in depth: even if a future discount rule goes wrong, an order
    # must never pay money out to the shopper.
    if total < 0:
        raise InvalidCart("order total cannot be negative")
    return total.quantize(CENT)
