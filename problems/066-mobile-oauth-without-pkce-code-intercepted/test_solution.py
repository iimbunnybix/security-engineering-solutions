import unittest

from solution import (
    CLIENT_ID,
    CODE_TTL_SECONDS,
    REDIRECT_URI,
    FakeClock,
    NaiveAuthServer,
    OAuthError,
    PkceAuthServer,
    code_from_redirect,
    generate_code_verifier,
    is_valid_verifier,
    s256_challenge,
)

USER = "meera"
# Public test vector from RFC 7636 Appendix B.
RFC_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
RFC_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


class ReproduceProblem(unittest.TestCase):
    def test_malicious_app_with_the_same_scheme_redeems_an_intercepted_code(self):
        server = NaiveAuthServer()
        redirect = server.authorize(USER, CLIENT_ID, REDIRECT_URI)
        # The OS delivered myapp://callback?code=... to the look-alike app.
        stolen_code = code_from_redirect(redirect)
        tokens = server.exchange(stolen_code, CLIENT_ID, REDIRECT_URI)
        self.assertEqual(tokens["user"], USER)

    def test_naive_token_endpoint_asks_for_nothing_but_public_values(self):
        server = NaiveAuthServer()
        code = code_from_redirect(server.authorize(USER, CLIENT_ID, REDIRECT_URI))
        self.assertIn("access_token", server.exchange(code, CLIENT_ID, REDIRECT_URI))


class FixS256Challenge(unittest.TestCase):
    def test_s256_matches_rfc_7636_appendix_b(self):
        self.assertEqual(s256_challenge(RFC_VERIFIER), RFC_CHALLENGE)

    def test_challenge_has_no_base64_padding(self):
        self.assertNotIn("=", s256_challenge(generate_code_verifier()))

    def test_generated_verifiers_are_valid_and_unique(self):
        first, second = generate_code_verifier(), generate_code_verifier()
        self.assertTrue(is_valid_verifier(first))
        self.assertNotEqual(first, second)

    def test_verifier_length_limits_are_43_and_128(self):
        self.assertFalse(is_valid_verifier("a" * 42))
        self.assertTrue(is_valid_verifier("a" * 43))
        self.assertTrue(is_valid_verifier("a" * 128))
        self.assertFalse(is_valid_verifier("a" * 129))

    def test_verifier_outside_unreserved_set_is_invalid(self):
        self.assertFalse(is_valid_verifier("a" * 42 + "+"))
        self.assertTrue(is_valid_verifier("a" * 40 + "-._~"))


class FixPkceServer(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.server = PkceAuthServer(self.clock, {CLIENT_ID: REDIRECT_URI})
        self.verifier = generate_code_verifier()

    def start_flow(self):
        redirect = self.server.authorize(USER, CLIENT_ID, REDIRECT_URI,
                                         s256_challenge(self.verifier), "S256")
        return code_from_redirect(redirect)

    def assert_error(self, expected_code, call, *args):
        with self.assertRaises(OAuthError) as raised:
            call(*args)
        self.assertEqual(raised.exception.code, expected_code)

    def test_real_app_with_the_verifier_gets_tokens(self):
        tokens = self.server.exchange(self.start_flow(), CLIENT_ID, REDIRECT_URI, self.verifier)
        self.assertEqual(tokens["user"], USER)

    def test_intercepted_code_without_verifier_is_rejected(self):
        self.assert_error("invalid_request", self.server.exchange,
                          self.start_flow(), CLIENT_ID, REDIRECT_URI, None)

    def test_intercepted_code_with_attackers_own_verifier_is_rejected(self):
        self.assert_error("invalid_grant", self.server.exchange,
                          self.start_flow(), CLIENT_ID, REDIRECT_URI, generate_code_verifier())

    def test_failed_attempt_burns_the_code_for_everyone(self):
        code = self.start_flow()
        self.assertRaises(OAuthError, self.server.exchange, code, CLIENT_ID, REDIRECT_URI,
                          generate_code_verifier())
        self.assert_error("invalid_grant", self.server.exchange,
                          code, CLIENT_ID, REDIRECT_URI, self.verifier)

    def test_code_is_single_use(self):
        code = self.start_flow()
        self.server.exchange(code, CLIENT_ID, REDIRECT_URI, self.verifier)
        self.assert_error("invalid_grant", self.server.exchange,
                          code, CLIENT_ID, REDIRECT_URI, self.verifier)

    def test_code_expires_after_its_ttl(self):
        code = self.start_flow()
        self.clock.now += CODE_TTL_SECONDS
        self.assert_error("invalid_grant", self.server.exchange,
                          code, CLIENT_ID, REDIRECT_URI, self.verifier)

    def test_code_is_accepted_just_before_expiry(self):
        code = self.start_flow()
        self.clock.now += CODE_TTL_SECONDS - 1
        self.assertIn("access_token", self.server.exchange(code, CLIENT_ID, REDIRECT_URI, self.verifier))

    def test_plain_method_is_refused(self):
        self.assert_error("invalid_request", self.server.authorize,
                          USER, CLIENT_ID, REDIRECT_URI, self.verifier, "plain")

    def test_missing_method_is_refused_rather_than_defaulting_to_plain(self):
        self.assert_error("invalid_request", self.server.authorize,
                          USER, CLIENT_ID, REDIRECT_URI, s256_challenge(self.verifier), None)

    def test_missing_challenge_is_refused(self):
        self.assert_error("invalid_request", self.server.authorize,
                          USER, CLIENT_ID, REDIRECT_URI, None, "S256")

    def test_unregistered_redirect_uri_is_refused(self):
        self.assert_error("invalid_request", self.server.authorize,
                          USER, CLIENT_ID, "evilapp://callback", s256_challenge(self.verifier), "S256")

    def test_redirect_uri_must_match_at_exchange(self):
        self.assert_error("invalid_grant", self.server.exchange,
                          self.start_flow(), CLIENT_ID, "evilapp://callback", self.verifier)

    def test_server_stores_only_a_hash_of_the_code(self):
        code = self.start_flow()
        self.assertNotIn(code, self.server.grants)


if __name__ == "__main__":
    unittest.main()
