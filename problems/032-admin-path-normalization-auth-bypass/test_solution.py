import unittest

from solution import (ROUTES, BadRequest, User, canonicalize, is_admin_area, original_handle,
                      safe_handle)

CUSTOMER = User("priya", is_admin=False)
ADMIN = User("ops-lead", is_admin=True)

BYPASS_PATHS = [
    "/ADMIN/users",
    "/Admin/refunds",
    "//admin/users",
    "/./admin/users",
    "/products/../admin/users",
    "/%61dmin/users",
    "/;x=1/admin/users",
]


class ReproduceProblem(unittest.TestCase):
    def test_plain_admin_path_is_blocked_for_a_customer(self):
        self.assertEqual(original_handle("/admin/users", CUSTOMER)[0], 403)

    def test_every_variant_reaches_the_admin_handler(self):
        for path in BYPASS_PATHS:
            with self.subTest(path=path):
                status, body = original_handle(path, CUSTOMER)
                self.assertEqual(status, 200)
                self.assertTrue(body.startswith("ADMIN"))

    def test_encoded_slash_variant_reaches_the_admin_handler(self):
        status, body = original_handle("/products/..%2fadmin/users", CUSTOMER)
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith("ADMIN"))


class FixCanonicalPathForAuthAndRouting(unittest.TestCase):
    def test_customer_is_refused_on_every_variant(self):
        for path in BYPASS_PATHS:
            with self.subTest(path=path):
                self.assertEqual(safe_handle(path, CUSTOMER)[0], 403)

    def test_admin_can_use_the_same_variants(self):
        for path in BYPASS_PATHS:
            with self.subTest(path=path):
                self.assertEqual(safe_handle(path, ADMIN)[0], 200)

    def test_public_pages_still_work_for_customers(self):
        self.assertEqual(safe_handle("/products", CUSTOMER), (200, ROUTES["/products"]))
        self.assertEqual(safe_handle("/products?page=2", CUSTOMER)[0], 200)
        self.assertEqual(safe_handle("/", CUSTOMER)[0], 200)

    def test_trailing_slash_is_still_protected(self):
        self.assertEqual(safe_handle("/admin/users/", CUSTOMER)[0], 403)

    def test_bare_admin_prefix_is_protected(self):
        self.assertEqual(safe_handle("/admin", CUSTOMER)[0], 403)

    def test_similar_name_outside_admin_area_is_not_treated_as_admin(self):
        self.assertFalse(is_admin_area("/administrators-guide"))
        self.assertEqual(safe_handle("/administrators-guide", CUSTOMER)[0], 404)

    def test_query_string_does_not_affect_authorization(self):
        self.assertEqual(safe_handle("/admin/users?next=/products", CUSTOMER)[0], 403)


class FixRejectsAmbiguousPaths(unittest.TestCase):
    def test_encoded_slash_is_rejected(self):
        self.assertEqual(safe_handle("/admin%2fusers", CUSTOMER)[0], 400)
        self.assertEqual(safe_handle("/products/..%2fadmin/users", CUSTOMER)[0], 400)

    def test_double_encoding_is_rejected(self):
        self.assertEqual(safe_handle("/%2561dmin/users", CUSTOMER)[0], 400)

    def test_backslash_is_rejected(self):
        self.assertEqual(safe_handle("/admin\\users", CUSTOMER)[0], 400)

    def test_encoded_null_byte_is_rejected(self):
        self.assertEqual(safe_handle("/admin%00/users", CUSTOMER)[0], 400)

    def test_dot_dot_above_root_is_rejected(self):
        self.assertEqual(safe_handle("/../admin/users", CUSTOMER)[0], 400)
        self.assertEqual(safe_handle("/%2e%2e/admin/users", CUSTOMER)[0], 400)

    def test_relative_path_is_rejected(self):
        with self.assertRaises(BadRequest):
            canonicalize("admin/users")

    def test_canonical_form_is_what_the_router_uses(self):
        self.assertEqual(canonicalize("//Products/./"), "/products")


if __name__ == "__main__":
    unittest.main()
