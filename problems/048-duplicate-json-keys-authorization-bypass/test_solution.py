import unittest

from solution import (HTTP_BAD_REQUEST, HTTP_CREATED, HTTP_FORBIDDEN, AccountService,
                      DuplicateKeyError, gateway_signup, naive_gateway_signup, strict_loads)

EMAIL = "mallory@example.com"
SMUGGLED_ADMIN = '{"email": "mallory@example.com", "role": "user", "role": "admin"}'
ESCAPED_ADMIN = '{"email": "mallory@example.com", "role": "user", "\\u0072ole": "admin"}'
NORMAL_SIGNUP = '{"email": "alice@example.com", "role": "user"}'


class ReproduceProblem(unittest.TestCase):
    def test_duplicate_role_key_creates_an_admin(self):
        backend = AccountService()
        status, _ = naive_gateway_signup(SMUGGLED_ADMIN, backend)
        self.assertEqual(status, HTTP_CREATED)
        self.assertEqual(backend.accounts[EMAIL], "admin")

    def test_unicode_escaped_duplicate_also_creates_an_admin(self):
        backend = AccountService()
        naive_gateway_signup(ESCAPED_ADMIN, backend)
        self.assertEqual(backend.accounts[EMAIL], "admin")

    def test_plain_admin_request_is_blocked(self):
        body = '{"email": "mallory@example.com", "role": "admin"}'
        status, _ = naive_gateway_signup(body, AccountService())
        self.assertEqual(status, HTTP_FORBIDDEN)


class FixRejectDuplicateKeys(unittest.TestCase):
    def test_duplicate_role_key_is_rejected(self):
        backend = AccountService()
        status, body = gateway_signup(SMUGGLED_ADMIN, backend)
        self.assertEqual(status, HTTP_BAD_REQUEST)
        self.assertIn("role", body["error"])
        self.assertEqual(backend.accounts, {})

    def test_unicode_escaped_duplicate_is_rejected(self):
        status, _ = gateway_signup(ESCAPED_ADMIN, AccountService())
        self.assertEqual(status, HTTP_BAD_REQUEST)

    def test_duplicate_inside_a_nested_object_is_rejected(self):
        with self.assertRaises(DuplicateKeyError):
            strict_loads('{"profile": {"name": "a", "name": "b"}}')

    def test_duplicate_inside_a_list_of_objects_is_rejected(self):
        with self.assertRaises(DuplicateKeyError):
            strict_loads('{"items": [{"id": 1, "id": 2}]}')

    def test_same_key_in_sibling_objects_is_allowed(self):
        data = strict_loads('{"a": {"id": 1}, "b": {"id": 2}}')
        self.assertEqual(data["b"]["id"], 2)


class FixNormalBehaviour(unittest.TestCase):
    def test_normal_signup_creates_a_user(self):
        backend = AccountService()
        status, _ = gateway_signup(NORMAL_SIGNUP, backend)
        self.assertEqual(status, HTTP_CREATED)
        self.assertEqual(backend.accounts["alice@example.com"], "user")

    def test_plain_admin_request_is_still_blocked(self):
        body = '{"email": "mallory@example.com", "role": "admin"}'
        status, _ = gateway_signup(body, AccountService())
        self.assertEqual(status, HTTP_FORBIDDEN)

    def test_invalid_json_is_a_bad_request(self):
        status, _ = gateway_signup('{"email": ', AccountService())
        self.assertEqual(status, HTTP_BAD_REQUEST)

    def test_non_object_body_is_forbidden(self):
        status, _ = gateway_signup('["role", "admin"]', AccountService())
        self.assertEqual(status, HTTP_FORBIDDEN)


if __name__ == "__main__":
    unittest.main()
