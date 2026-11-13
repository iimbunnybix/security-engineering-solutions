import unittest

from solution import is_allowed, naive_is_allowed, parse_redirect_uri

# Patterns as the client developer typed them into the old registration form.
NAIVE_PATTERNS = [
    "https://app.example.com/oauth/callback",
    "https://.*.example.com/oauth/callback",
]
# The exact URIs the same client registers after the fix.
REGISTERED_URIS = [
    "https://app.example.com/oauth/callback",
    "https://eu.example.com/oauth/callback",
]
GOOD_URI = "https://app.example.com/oauth/callback"


class ReproduceProblem(unittest.TestCase):
    def test_unescaped_dot_matches_a_lookalike_domain(self):
        self.assertTrue(naive_is_allowed("https://appxexample.com/oauth/callback", NAIVE_PATTERNS))

    def test_wildcard_crosses_from_host_into_path(self):
        attacker = "https://attacker.test/?.example.com/oauth/callback"
        self.assertTrue(naive_is_allowed(attacker, NAIVE_PATTERNS))

    def test_prefix_match_accepts_extra_suffix(self):
        attacker = "https://app.example.com/oauth/callback/../../logout?next=https://attacker.test"
        self.assertTrue(naive_is_allowed(attacker, NAIVE_PATTERNS))


class FixExactMatch(unittest.TestCase):
    def test_registered_uri_is_allowed(self):
        self.assertTrue(is_allowed(GOOD_URI, REGISTERED_URIS))

    def test_lookalike_domain_is_rejected(self):
        self.assertFalse(is_allowed("https://appxexample.com/oauth/callback", REGISTERED_URIS))

    def test_attacker_host_with_lookalike_path_is_rejected(self):
        self.assertFalse(is_allowed("https://attacker.test/?.example.com/oauth/callback", REGISTERED_URIS))

    def test_extra_path_or_query_is_rejected(self):
        self.assertFalse(is_allowed(GOOD_URI + "/../../logout", REGISTERED_URIS))
        self.assertFalse(is_allowed(GOOD_URI + "?next=https://attacker.test", REGISTERED_URIS))

    def test_suffix_domain_is_rejected(self):
        self.assertFalse(is_allowed("https://app.example.com.attacker.test/oauth/callback", REGISTERED_URIS))

    def test_userinfo_trick_is_rejected(self):
        self.assertFalse(is_allowed("https://app.example.com@attacker.test/oauth/callback", REGISTERED_URIS))

    def test_fragment_is_rejected(self):
        self.assertFalse(is_allowed(GOOD_URI + "#x", REGISTERED_URIS))

    def test_plain_http_is_rejected(self):
        self.assertFalse(is_allowed("http://app.example.com/oauth/callback", REGISTERED_URIS))

    def test_host_case_and_default_port_do_not_matter(self):
        self.assertTrue(is_allowed("https://APP.example.com:443/oauth/callback", REGISTERED_URIS))

    def test_other_port_is_rejected(self):
        self.assertFalse(is_allowed("https://app.example.com:8443/oauth/callback", REGISTERED_URIS))

    def test_malformed_port_is_rejected_not_crashing(self):
        self.assertIsNone(parse_redirect_uri("https://app.example.com:99999/oauth/callback"))
        self.assertFalse(is_allowed("https://app.example.com:abc/oauth/callback", REGISTERED_URIS))


if __name__ == "__main__":
    unittest.main()
