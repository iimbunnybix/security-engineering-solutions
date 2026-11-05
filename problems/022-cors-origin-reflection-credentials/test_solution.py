import unittest

from solution import (
    CorsPolicy,
    browser_lets_page_read_response,
    naive_cors_headers,
    naive_substring_check,
    naive_suffix_check,
    parse_origin,
)

APP_ORIGIN = "https://app.example.com"
ADMIN_ORIGIN = "https://admin.example.com:8443"
ATTACKER_ORIGIN = "https://attacker.test"


def production_policy() -> CorsPolicy:
    return CorsPolicy([APP_ORIGIN, ADMIN_ORIGIN])


class ReproduceProblem(unittest.TestCase):
    def test_reflection_lets_any_site_read_credentialed_responses(self):
        headers = naive_cors_headers(ATTACKER_ORIGIN)
        self.assertTrue(browser_lets_page_read_response(ATTACKER_ORIGIN, headers))

    def test_reflection_trusts_the_null_origin(self):
        headers = naive_cors_headers("null")
        self.assertTrue(browser_lets_page_read_response("null", headers))

    def test_suffix_check_trusts_a_lookalike_domain(self):
        self.assertTrue(naive_suffix_check("https://evil-example.com", "example.com"))

    def test_substring_check_trusts_an_attacker_subdomain(self):
        self.assertTrue(naive_substring_check("https://example.com.attacker.net", "example.com"))


class FixAllowsOnlyExactOrigins(unittest.TestCase):
    def test_allowlisted_origin_can_read_the_response(self):
        headers = production_policy().cors_headers(APP_ORIGIN)
        self.assertTrue(browser_lets_page_read_response(APP_ORIGIN, headers))

    def test_attacker_origin_gets_no_allow_headers(self):
        headers = production_policy().cors_headers(ATTACKER_ORIGIN)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertFalse(browser_lets_page_read_response(ATTACKER_ORIGIN, headers))

    def test_lookalike_and_attacker_subdomain_are_refused(self):
        policy = production_policy()
        for origin in ["https://evil-app.example.com", "https://app.example.com.attacker.net",
                       "https://xapp.example.com", "https://example.com"]:
            with self.subTest(origin=origin):
                self.assertFalse(policy.is_allowed(origin))

    def test_null_origin_is_never_trusted(self):
        self.assertFalse(production_policy().is_allowed("null"))

    def test_plain_http_version_of_an_allowed_origin_is_refused(self):
        self.assertFalse(production_policy().is_allowed("http://app.example.com"))

    def test_wrong_port_is_refused(self):
        self.assertFalse(production_policy().is_allowed("https://admin.example.com"))
        self.assertTrue(production_policy().is_allowed(ADMIN_ORIGIN))

    def test_origin_with_path_or_user_info_is_refused(self):
        policy = production_policy()
        for origin in ["https://app.example.com/", "https://app.example.com@attacker.test",
                       "https://app.example.com?x=1", " https://app.example.com"]:
            with self.subTest(origin=origin):
                self.assertFalse(policy.is_allowed(origin))

    def test_missing_origin_header_gets_no_allow_headers(self):
        self.assertEqual(production_policy().cors_headers(None), {"Vary": "Origin"})


class FixHandlesNormalisationAndCaching(unittest.TestCase):
    def test_explicit_default_port_and_uppercase_host_match(self):
        headers = production_policy().cors_headers("https://APP.example.com:443")
        self.assertEqual(headers["Access-Control-Allow-Origin"], APP_ORIGIN)

    def test_vary_origin_is_sent_on_allowed_and_refused_responses(self):
        policy = production_policy()
        self.assertEqual(policy.cors_headers(APP_ORIGIN)["Vary"], "Origin")
        self.assertEqual(policy.cors_headers(ATTACKER_ORIGIN)["Vary"], "Origin")

    def test_invalid_allowlist_entry_fails_at_startup(self):
        with self.assertRaises(ValueError):
            CorsPolicy(["app.example.com"])

    def test_non_numeric_port_does_not_crash(self):
        self.assertIsNone(parse_origin("https://app.example.com:abc"))

    def test_unsupported_scheme_is_rejected(self):
        self.assertIsNone(parse_origin("ftp://app.example.com"))


if __name__ == "__main__":
    unittest.main()
