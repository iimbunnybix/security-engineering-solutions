import unittest

from solution import (
    DIGEST_HEX_LENGTH,
    InvalidSignature,
    compute_signature_hex,
    naive_truncated_compare_verify,
    naive_verify,
    verify_webhook,
)

PAYOUT_BODY = b'{"payout_id": "po_1001", "status": "paid", "amount": 250000}'


def signing_secret() -> bytes:
    """Built at runtime so no secret-looking literal sits in the repo."""
    return ("test-" + "webhook-" + "signing-key").encode()


def header_for(signature_hex: str) -> str:
    return "sha256=" + signature_hex


def correct_header(body: bytes = PAYOUT_BODY) -> str:
    return header_for(compute_signature_hex(signing_secret(), body))


class ReproduceProblem(unittest.TestCase):
    def test_empty_signature_is_accepted_by_the_prefix_check(self):
        self.assertTrue(naive_verify(signing_secret(), PAYOUT_BODY, header_for("")))

    def test_one_correct_hex_digit_is_accepted_by_the_prefix_check(self):
        first_digit = compute_signature_hex(signing_secret(), PAYOUT_BODY)[0]
        self.assertTrue(naive_verify(signing_secret(), PAYOUT_BODY, header_for(first_digit)))

    def test_guessing_one_digit_forges_a_request_within_sixteen_tries(self):
        accepted = [digit for digit in "0123456789abcdef"
                    if naive_verify(signing_secret(), PAYOUT_BODY, header_for(digit))]
        self.assertEqual(len(accepted), 1)

    def test_truncated_constant_time_compare_still_accepts_empty_signature(self):
        self.assertTrue(naive_truncated_compare_verify(signing_secret(), PAYOUT_BODY, header_for("")))


class FixRequiresTheFullDigest(unittest.TestCase):
    def assertRejected(self, header_value):
        with self.assertRaises(InvalidSignature):
            verify_webhook(signing_secret(), PAYOUT_BODY, header_value)

    def test_correct_signature_is_accepted(self):
        verify_webhook(signing_secret(), PAYOUT_BODY, correct_header())

    def test_uppercase_hex_of_the_correct_signature_is_accepted(self):
        verify_webhook(signing_secret(), PAYOUT_BODY, correct_header().upper().replace("SHA256=", "sha256="))

    def test_empty_signature_is_rejected(self):
        self.assertRejected(header_for(""))

    def test_correct_prefix_alone_is_rejected(self):
        full_hex = compute_signature_hex(signing_secret(), PAYOUT_BODY)
        self.assertRejected(header_for(full_hex[:DIGEST_HEX_LENGTH - 1]))

    def test_correct_signature_with_extra_characters_is_rejected(self):
        self.assertRejected(correct_header() + "00")

    def test_signature_for_a_different_body_is_rejected(self):
        self.assertRejected(correct_header(b'{"payout_id": "po_1001", "status": "failed"}'))

    def test_last_byte_flipped_is_rejected(self):
        full_hex = compute_signature_hex(signing_secret(), PAYOUT_BODY)
        flipped_last_digit = "0" if full_hex[-1] != "0" else "1"
        self.assertRejected(header_for(full_hex[:-1] + flipped_last_digit))

    def test_missing_header_is_rejected(self):
        self.assertRejected(None)

    def test_wrong_scheme_is_rejected(self):
        self.assertRejected(correct_header().replace("sha256=", "sha1="))

    def test_non_hex_signature_of_the_right_length_is_rejected(self):
        self.assertRejected(header_for("z" * DIGEST_HEX_LENGTH))

    def test_spaces_inside_the_signature_are_rejected(self):
        full_hex = compute_signature_hex(signing_secret(), PAYOUT_BODY)
        self.assertRejected(header_for(full_hex[:30] + "  " + full_hex[32:]))


if __name__ == "__main__":
    unittest.main()
