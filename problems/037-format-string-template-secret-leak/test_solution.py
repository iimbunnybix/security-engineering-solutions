import unittest

import solution
from solution import (Customer, Order, TemplateError, naive_render_template,
                      render_template)

SECRET_TEMPLATE = "Tracking: {order.__init__.__globals__[WEBHOOK_SIGNING_KEY]}"


def make_customer() -> Customer:
    return Customer(name="Asha", email="asha@example.test")


def make_order() -> Order:
    return Order(order_id="A-1001", total="49.90")


class ReproduceProblem(unittest.TestCase):
    def test_naive_renderer_leaks_the_signing_key(self):
        rendered = naive_render_template(SECRET_TEMPLATE, make_customer(), make_order())
        self.assertIn(solution.WEBHOOK_SIGNING_KEY, rendered)

    def test_naive_renderer_exposes_object_internals(self):
        rendered = naive_render_template("{customer.__dict__}", make_customer(), make_order())
        self.assertIn("asha@example.test", rendered)


class FixRenderTemplate(unittest.TestCase):
    def render(self, template: str) -> str:
        return render_template(template, make_customer(), make_order())

    def test_normal_template_renders(self):
        self.assertEqual(self.render("Hi {customer.name}, order {order.id} ({order.total}) shipped"),
                         "Hi Asha, order A-1001 (49.90) shipped")

    def test_globals_walk_is_rejected(self):
        with self.assertRaises(TemplateError):
            self.render(SECRET_TEMPLATE)

    def test_dunder_attribute_is_rejected(self):
        with self.assertRaises(TemplateError):
            self.render("{customer.__dict__}")

    def test_bare_object_placeholder_is_rejected(self):
        with self.assertRaises(TemplateError):
            self.render("{order}")

    def test_index_access_is_rejected(self):
        with self.assertRaises(TemplateError):
            self.render("{customer.name[0]}")

    def test_conversion_is_rejected(self):
        with self.assertRaises(TemplateError):
            self.render("{customer.name!r}")

    def test_huge_padding_format_spec_is_rejected(self):
        with self.assertRaises(TemplateError):
            self.render("{order.id:>999999999}")

    def test_unmatched_brace_is_a_template_error(self):
        with self.assertRaises(TemplateError):
            self.render("Hi {customer.name")

    def test_escaped_braces_stay_literal(self):
        self.assertEqual(self.render("{{order.id}} is {order.id}"), "{order.id} is A-1001")

    def test_braces_inside_customer_data_are_not_re_rendered(self):
        customer = Customer(name="{order.__init__.__globals__}", email="x@example.test")
        rendered = render_template("Hi {customer.name}", customer, make_order())
        self.assertEqual(rendered, "Hi {order.__init__.__globals__}")

    def test_overlong_template_is_rejected(self):
        with self.assertRaises(TemplateError):
            self.render("x" * 2001)


if __name__ == "__main__":
    unittest.main()
