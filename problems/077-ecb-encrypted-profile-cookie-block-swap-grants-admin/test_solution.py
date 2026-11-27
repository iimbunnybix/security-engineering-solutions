import secrets
import unittest

from solution import (BLOCK_SIZE, InvalidToken, ecb_decrypt, ecb_encrypt,
                      forge_admin_cookie_by_block_swap, issue_signed_token,
                      original_issue_cookie, original_read_cookie, pkcs7_pad,
                      read_signed_token, split_blocks, toy_decrypt_block,
                      toy_encrypt_block)

ATTACKER_UID = 1042
CRAFTED_ADMIN_EMAIL = "A" * 10 + pkcs7_pad(b"admin").decode("latin-1")


def new_key() -> bytes:
    return secrets.token_bytes(16)


class ToyCipher(unittest.TestCase):
    def test_block_round_trips(self):
        key, block = new_key(), secrets.token_bytes(BLOCK_SIZE)
        self.assertEqual(toy_decrypt_block(key, toy_encrypt_block(key, block)), block)

    def test_messages_of_every_length_round_trip(self):
        key = new_key()
        for length in range(0, 40):
            with self.subTest(length=length):
                message = secrets.token_bytes(length)
                self.assertEqual(ecb_decrypt(key, ecb_encrypt(key, message)), message)


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.key = new_key()

    def register(self, email: str) -> bytes:
        return original_issue_cookie(self.key, email, ATTACKER_UID)

    def test_normal_cookie_says_role_user(self):
        self.assertEqual(original_read_cookie(self.key, self.register("eve@evil.test"))["role"], "user")

    def test_equal_plaintext_blocks_give_equal_ciphertext_blocks(self):
        blocks = split_blocks(ecb_encrypt(self.key, b"Y" * BLOCK_SIZE * 2))
        self.assertEqual(blocks[0], blocks[1])

    def test_block_swap_forges_an_admin_cookie_without_the_key(self):
        forged = forge_admin_cookie_by_block_swap(self.register)
        profile = original_read_cookie(self.key, forged)
        self.assertEqual(profile["role"], "admin")
        self.assertEqual(profile["email"], "eeeeeeeeee@evil.test")

    def test_forgery_needs_only_three_blocks_from_two_registrations(self):
        self.assertEqual(len(forge_admin_cookie_by_block_swap(self.register)), 3 * BLOCK_SIZE)


class FixSignedToken(unittest.TestCase):
    def setUp(self):
        self.key = new_key()

    def register(self, email: str) -> str:
        return issue_signed_token(self.key, email, ATTACKER_UID)

    def test_genuine_token_is_accepted(self):
        profile = read_signed_token(self.key, self.register("eve@evil.test"))
        self.assertEqual(profile, {"email": "eve@evil.test", "role": "user", "uid": ATTACKER_UID})

    def test_crafted_admin_email_stays_an_email_and_role_stays_user(self):
        profile = read_signed_token(self.key, self.register(CRAFTED_ADMIN_EMAIL))
        self.assertEqual(profile["email"], CRAFTED_ADMIN_EMAIL)
        self.assertEqual(profile["role"], "user")

    def test_email_cannot_inject_a_role_field(self):
        profile = read_signed_token(self.key, self.register('x@y.z","role":"admin'))
        self.assertEqual(profile["role"], "user")

    def test_splicing_pieces_of_two_tokens_is_rejected_at_every_cut_point(self):
        first = self.register(CRAFTED_ADMIN_EMAIL)
        second = self.register("eeeeeeeeee@evil.test")
        for cut in range(1, min(len(first), len(second))):
            spliced = second[:cut] + first[cut:]
            if spliced in (first, second):
                continue
            with self.subTest(cut=cut):
                with self.assertRaises(InvalidToken):
                    read_signed_token(self.key, spliced)

    def test_payload_of_one_token_with_tag_of_another_is_rejected(self):
        payload = self.register("a@b.c").split(".")[0]
        tag = self.register("d@e.f").split(".")[1]
        with self.assertRaises(InvalidToken):
            read_signed_token(self.key, payload + "." + tag)

    def test_token_signed_with_another_key_is_rejected(self):
        foreign = issue_signed_token(new_key(), "eve@evil.test", ATTACKER_UID)
        with self.assertRaises(InvalidToken):
            read_signed_token(self.key, foreign)

    def test_malformed_tokens_are_rejected(self):
        for token in ("", "no-separator", ".tagonly", "payload."):
            with self.subTest(token=token):
                with self.assertRaises(InvalidToken):
                    read_signed_token(self.key, token)


if __name__ == "__main__":
    unittest.main()
