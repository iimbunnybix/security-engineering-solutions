import unittest

from solution import (AUTHENTICATED, PUBLIC, STATUS_FORBIDDEN, STATUS_NOT_FOUND, STATUS_OK,
                      STATUS_UNAUTHENTICATED, NaiveRouter, Response, RouteConfigError, SecureRouter, User,
                      unapproved_public_routes)

EXPORT_PATH = "/api/reports/customers.csv"
CUSTOMER_EXPORT = "id,email\n1,customer@example.test"
ANALYST = User("analyst-1", frozenset({"reports:read"}))
SHOPPER = User("shopper-9")
ANONYMOUS = None


def export_customers(_user):
    return CUSTOMER_EXPORT


def show_homepage(_user):
    return "welcome"


def show_profile(user):
    return f"profile of {user.user_id}"


def build_secure_router():
    router = SecureRouter()
    router.add("/", show_homepage, access=PUBLIC)
    router.add("/me", show_profile, access=AUTHENTICATED)
    router.add(EXPORT_PATH, export_customers, access="reports:read")
    return router


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.router = NaiveRouter()
        # The new route was added without permission=..., exactly as in the incident.
        self.router.add(EXPORT_PATH, export_customers)

    def test_anonymous_visitor_downloads_the_customer_export(self):
        response = self.router.dispatch(EXPORT_PATH, ANONYMOUS)
        self.assertEqual(response, Response(STATUS_OK, CUSTOMER_EXPORT))

    def test_logged_in_shopper_downloads_the_customer_export(self):
        self.assertEqual(self.router.dispatch(EXPORT_PATH, SHOPPER).status, STATUS_OK)


class FixDenyByDefaultRouter(unittest.TestCase):
    def setUp(self):
        self.router = build_secure_router()

    def test_route_without_access_rule_cannot_be_registered(self):
        with self.assertRaises(TypeError):
            SecureRouter().add(EXPORT_PATH, export_customers)

    def test_empty_or_blank_access_rule_is_rejected(self):
        for bad_access in ["", "   ", None]:
            with self.subTest(access=bad_access):
                with self.assertRaises(RouteConfigError):
                    SecureRouter().add(EXPORT_PATH, export_customers, access=bad_access)

    def test_registering_the_same_path_twice_is_rejected(self):
        with self.assertRaises(RouteConfigError):
            self.router.add(EXPORT_PATH, show_homepage, access=PUBLIC)

    def test_anonymous_visitor_is_asked_to_log_in(self):
        self.assertEqual(self.router.dispatch(EXPORT_PATH, ANONYMOUS).status, STATUS_UNAUTHENTICATED)

    def test_shopper_without_permission_is_forbidden(self):
        self.assertEqual(self.router.dispatch(EXPORT_PATH, SHOPPER).status, STATUS_FORBIDDEN)

    def test_analyst_with_permission_gets_the_export(self):
        self.assertEqual(self.router.dispatch(EXPORT_PATH, ANALYST), Response(STATUS_OK, CUSTOMER_EXPORT))

    def test_explicitly_public_route_works_for_anonymous_visitors(self):
        self.assertEqual(self.router.dispatch("/", ANONYMOUS), Response(STATUS_OK, "welcome"))

    def test_authenticated_route_needs_a_login_but_no_permission(self):
        self.assertEqual(self.router.dispatch("/me", ANONYMOUS).status, STATUS_UNAUTHENTICATED)
        self.assertEqual(self.router.dispatch("/me", SHOPPER).body, "profile of shopper-9")

    def test_misspelled_permission_denies_everyone_instead_of_allowing(self):
        self.router.add("/api/reports/orders.csv", export_customers, access="reports:reed")
        self.assertEqual(self.router.dispatch("/api/reports/orders.csv", ANALYST).status, STATUS_FORBIDDEN)

    def test_unknown_path_is_not_found(self):
        self.assertEqual(self.router.dispatch("/api/nope", ANALYST).status, STATUS_NOT_FOUND)

    def test_audit_lists_every_route_with_its_rule(self):
        self.assertEqual(self.router.audit(), [
            ("/", PUBLIC),
            ("/api/reports/customers.csv", "reports:read"),
            ("/me", AUTHENTICATED),
        ])

    def test_ci_check_flags_a_public_route_nobody_approved(self):
        self.router.add("/api/debug/config", show_homepage, access=PUBLIC)
        self.assertEqual(unapproved_public_routes(self.router, approved={"/"}), ["/api/debug/config"])


if __name__ == "__main__":
    unittest.main()
