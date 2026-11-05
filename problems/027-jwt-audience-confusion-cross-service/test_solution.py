import secrets
import unittest

from solution import (
    PAYMENTS_ADMIN_SERVICE,
    REPORTING_SERVICE,
    TRUSTED_ISSUER,
    InvalidToken,
    naive_verify,
    sign,
    verify_for_service,
)

NOW = 1_790_000_000
FIVE_MINUTES = 300


def new_shared_key():
    return secrets.token_bytes(32)


def claims_for(audience, issuer=TRUSTED_ISSUER, scope="reports:read", lifetime=FIVE_MINUTES):
    claims = {"sub": "analyst-42", "scope": scope, "exp": NOW + lifetime}
    if audience is not None:
        claims["aud"] = audience
    if issuer is not None:
        claims["iss"] = issuer
    return claims


class ReproduceProblem(unittest.TestCase):
    def test_reporting_token_is_accepted_by_payments_admin(self):
        key = new_shared_key()
        reporting_token = sign(key, claims_for(REPORTING_SERVICE))
        claims = naive_verify(key, reporting_token, NOW)
        self.assertEqual(claims["aud"], REPORTING_SERVICE)   # accepted anyway

    def test_token_without_aud_is_accepted(self):
        key = new_shared_key()
        token = sign(key, claims_for(None))
        self.assertEqual(naive_verify(key, token, NOW)["sub"], "analyst-42")


class FixChecksAudienceAndIssuer(unittest.TestCase):
    def setUp(self):
        self.key = new_shared_key()

    def verify_at_payments(self, claims):
        return verify_for_service(self.key, sign(self.key, claims), NOW, PAYMENTS_ADMIN_SERVICE)

    def test_reporting_token_is_rejected_by_payments_admin(self):
        with self.assertRaisesRegex(InvalidToken, "not intended"):
            self.verify_at_payments(claims_for(REPORTING_SERVICE))

    def test_same_token_still_works_at_reporting(self):
        token = sign(self.key, claims_for(REPORTING_SERVICE))
        claims = verify_for_service(self.key, token, NOW, REPORTING_SERVICE)
        self.assertEqual(claims["sub"], "analyst-42")

    def test_token_for_payments_admin_is_accepted(self):
        claims = self.verify_at_payments(claims_for(PAYMENTS_ADMIN_SERVICE))
        self.assertEqual(claims["aud"], PAYMENTS_ADMIN_SERVICE)

    def test_audience_list_containing_this_service_is_accepted(self):
        claims = self.verify_at_payments(claims_for([REPORTING_SERVICE, PAYMENTS_ADMIN_SERVICE]))
        self.assertIn(PAYMENTS_ADMIN_SERVICE, claims["aud"])

    def test_audience_list_without_this_service_is_rejected(self):
        with self.assertRaises(InvalidToken):
            self.verify_at_payments(claims_for([REPORTING_SERVICE, "search-api"]))

    def test_missing_aud_is_rejected(self):
        with self.assertRaisesRegex(InvalidToken, "aud"):
            self.verify_at_payments(claims_for(None))

    def test_empty_or_malformed_aud_is_rejected(self):
        for bad_audience in ([], "", 123, [PAYMENTS_ADMIN_SERVICE, 7], {"x": 1}):
            with self.subTest(aud=bad_audience):
                with self.assertRaises(InvalidToken):
                    self.verify_at_payments(claims_for(bad_audience))

    def test_lookalike_audience_is_rejected(self):
        for lookalike in ("payments-admin-api-staging", "PAYMENTS-ADMIN-API", "payments-admin"):
            with self.subTest(aud=lookalike):
                with self.assertRaises(InvalidToken):
                    self.verify_at_payments(claims_for(lookalike))

    def test_missing_issuer_is_rejected(self):
        with self.assertRaisesRegex(InvalidToken, "iss"):
            self.verify_at_payments(claims_for(PAYMENTS_ADMIN_SERVICE, issuer=None))

    def test_wrong_issuer_is_rejected(self):
        with self.assertRaisesRegex(InvalidToken, "iss"):
            self.verify_at_payments(claims_for(PAYMENTS_ADMIN_SERVICE, issuer="https://evil.example"))


class SignatureAndExpiryStillChecked(unittest.TestCase):
    def setUp(self):
        self.key = new_shared_key()

    def test_token_signed_with_another_key_is_rejected(self):
        token = sign(new_shared_key(), claims_for(PAYMENTS_ADMIN_SERVICE))
        with self.assertRaisesRegex(InvalidToken, "signature"):
            verify_for_service(self.key, token, NOW, PAYMENTS_ADMIN_SERVICE)

    def test_editing_aud_breaks_the_signature(self):
        token = sign(self.key, claims_for(REPORTING_SERVICE))
        forged_payload = sign(self.key, claims_for(PAYMENTS_ADMIN_SERVICE)).split(".")[1]
        header, _, signature = token.split(".")
        with self.assertRaisesRegex(InvalidToken, "signature"):
            verify_for_service(self.key, f"{header}.{forged_payload}.{signature}", NOW,
                               PAYMENTS_ADMIN_SERVICE)

    def test_expired_token_is_rejected(self):
        token = sign(self.key, claims_for(PAYMENTS_ADMIN_SERVICE))
        with self.assertRaisesRegex(InvalidToken, "expired"):
            verify_for_service(self.key, token, NOW + FIVE_MINUTES + 60, PAYMENTS_ADMIN_SERVICE)

    def test_missing_exp_is_rejected(self):
        claims = claims_for(PAYMENTS_ADMIN_SERVICE)
        del claims["exp"]
        with self.assertRaisesRegex(InvalidToken, "exp"):
            verify_for_service(self.key, sign(self.key, claims), NOW, PAYMENTS_ADMIN_SERVICE)

    def test_malformed_tokens_raise_invalid_token(self):
        for garbage in ("", "a.b", "a.b.c.d", "!!!.###.$$$", "e30.e30.e30"):
            with self.subTest(token=garbage):
                with self.assertRaises(InvalidToken):
                    verify_for_service(self.key, garbage, NOW, PAYMENTS_ADMIN_SERVICE)


if __name__ == "__main__":
    unittest.main()
