import json
import unittest

from solution import (GENERIC_MESSAGE, ServerLog, create_order_with_bad_quantity, database_url,
                      get_order, naive_handle, safe_handle)


def fixed_error_id() -> str:
    return "err-0001"


def database_password() -> str:
    """The password part of the sample DSN, extracted the same way an attacker would."""
    return database_url().split(":")[2].split("@")[0]


class ReproduceProblem(unittest.TestCase):
    def test_500_body_contains_the_database_password(self):
        response = naive_handle(get_order)
        self.assertEqual(response.status, 500)
        self.assertIn(database_password(), response.body["error"])

    def test_500_body_reveals_internal_hostname_and_source_paths(self):
        body = naive_handle(get_order).body["error"]
        self.assertIn("db-primary.internal", body)
        self.assertIn("solution.py", body)


class FixGenericErrorResponse(unittest.TestCase):
    def setUp(self):
        self.log = ServerLog()
        self.response = safe_handle(get_order, self.log, fixed_error_id)

    def test_client_sees_only_a_generic_message_and_an_id(self):
        self.assertEqual(self.response.status, 500)
        self.assertEqual(self.response.body, {"error": GENERIC_MESSAGE, "error_id": "err-0001"})

    def test_no_internal_detail_appears_anywhere_in_the_response(self):
        serialized = json.dumps(self.response.body)
        for secret_detail in (database_password(), "db-primary.internal", "Traceback", ".py"):
            with self.subTest(detail=secret_detail):
                self.assertNotIn(secret_detail, serialized)

    def test_full_traceback_is_logged_under_the_same_id(self):
        error_id, details = self.log.entries[0]
        self.assertEqual(error_id, "err-0001")
        self.assertIn("ConnectionError", details)

    def test_default_error_ids_are_random_and_distinct(self):
        log = ServerLog()
        first = safe_handle(get_order, log).body["error_id"]
        second = safe_handle(get_order, log).body["error_id"]
        self.assertNotEqual(first, second)
        self.assertEqual(len(first), 16)


class FixDeliberateClientErrors(unittest.TestCase):
    def test_client_error_message_is_returned_with_400(self):
        response = safe_handle(create_order_with_bad_quantity, ServerLog())
        self.assertEqual(response.status, 400)
        self.assertEqual(response.body, {"error": "quantity must be a positive integer"})

    def test_value_error_from_a_library_is_not_shown_to_the_client(self):
        def handler() -> dict[str, str]:
            raise ValueError("invalid literal for int() with base 10: 'secret-table'")
        response = safe_handle(handler, ServerLog(), fixed_error_id)
        self.assertEqual(response.status, 500)
        self.assertNotIn("secret-table", json.dumps(response.body))

    def test_successful_handler_is_untouched(self):
        response = safe_handle(lambda: {"order": "o-1"}, ServerLog())
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body, {"order": "o-1"})


if __name__ == "__main__":
    unittest.main()
