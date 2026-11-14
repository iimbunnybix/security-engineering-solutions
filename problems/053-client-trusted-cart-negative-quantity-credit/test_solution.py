import unittest
from decimal import Decimal

from solution import InvalidCart, MAX_QUANTITY_PER_LINE, checkout_total, naive_checkout_total

CATALOG = {"headphones": Decimal("199.00"), "cable": Decimal("9.99")}


def line(sku: str, quantity: object, unit_price: str = "0") -> dict:
    """A cart line as the browser sends it, including the client-side price field."""
    return {"sku": sku, "quantity": quantity, "unit_price": unit_price}


class ReproduceProblem(unittest.TestCase):
    def test_negative_quantity_makes_order_total_negative(self):
        cart = [line("cable", 1, "9.99"), line("headphones", -2, "199.00")]
        self.assertEqual(naive_checkout_total(cart), -388.01)

    def test_edited_price_buys_headphones_for_one_cent(self):
        cart = [line("headphones", 1, "0.01")]
        self.assertEqual(naive_checkout_total(cart), 0.01)

    def test_fractional_quantity_is_charged_as_a_fraction(self):
        cart = [line("headphones", 0.01, "199.00")]
        self.assertEqual(naive_checkout_total(cart), 1.99)


class FixServerSidePricing(unittest.TestCase):
    def test_normal_cart_is_priced_from_catalog(self):
        cart = [line("headphones", 1), line("cable", 3)]
        self.assertEqual(checkout_total(cart, CATALOG), Decimal("228.97"))

    def test_client_price_is_ignored(self):
        cart = [line("headphones", 1, "0.01")]
        self.assertEqual(checkout_total(cart, CATALOG), Decimal("199.00"))

    def test_negative_quantity_is_rejected(self):
        with self.assertRaises(InvalidCart):
            checkout_total([line("cable", 1), line("headphones", -2)], CATALOG)

    def test_zero_quantity_is_rejected(self):
        with self.assertRaises(InvalidCart):
            checkout_total([line("cable", 0)], CATALOG)

    def test_fractional_quantity_is_rejected(self):
        with self.assertRaises(InvalidCart):
            checkout_total([line("headphones", 0.01)], CATALOG)

    def test_string_quantity_is_rejected(self):
        with self.assertRaises(InvalidCart):
            checkout_total([line("headphones", "1")], CATALOG)

    def test_boolean_quantity_is_rejected(self):
        with self.assertRaises(InvalidCart):
            checkout_total([line("headphones", True)], CATALOG)

    def test_huge_quantity_is_rejected(self):
        with self.assertRaises(InvalidCart):
            checkout_total([line("cable", MAX_QUANTITY_PER_LINE + 1)], CATALOG)

    def test_repeating_a_sku_cannot_bypass_the_quantity_limit(self):
        cart = [line("cable", MAX_QUANTITY_PER_LINE), line("cable", 1)]
        with self.assertRaises(InvalidCart):
            checkout_total(cart, CATALOG)

    def test_unknown_sku_is_rejected(self):
        with self.assertRaises(InvalidCart):
            checkout_total([line("gift-card", 1)], CATALOG)

    def test_empty_cart_is_rejected(self):
        with self.assertRaises(InvalidCart):
            checkout_total([], CATALOG)

    def test_negative_catalog_price_never_pays_out(self):
        broken_catalog = {"refund-adjustment": Decimal("-50.00")}
        with self.assertRaises(InvalidCart):
            checkout_total([line("refund-adjustment", 1)], broken_catalog)


if __name__ == "__main__":
    unittest.main()
