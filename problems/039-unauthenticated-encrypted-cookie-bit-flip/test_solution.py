import secrets
import unittest

from solution import (NONCE_BYTES, TAG_BYTES, InvalidCookie, encode_session, flip_bytes,
                      naive_open, naive_seal, open_sealed, seal, xor_bytes)

USER_SESSION = {"uid": "1042", "role": "user"}
ROLE_OFFSET = len(b"uid=1042;role=")


def make_key() -> bytes:
    """Fresh random key per test; never a literal."""
    return secrets.token_bytes(32)


class ReproduceProblem(unittest.TestCase):
    def test_attacker_turns_user_cookie_into_root_without_the_key(self):
        key = make_key()
        cookie = naive_seal(key, USER_SESSION)
        forged = flip_bytes(cookie, ROLE_OFFSET, b"user", b"root")
        self.assertEqual(naive_open(key, forged), {"uid": "1042", "role": "root"})

    def test_fixed_nonce_lets_two_cookies_cancel_the_keystream(self):
        key = make_key()
        first = naive_seal(key, {"uid": "1042", "role": "user"})
        second = naive_seal(key, {"uid": "7777", "role": "user"})
        plaintext_xor = xor_bytes(encode_session({"uid": "1042", "role": "user"}),
                                  encode_session({"uid": "7777", "role": "user"}))
        self.assertEqual(xor_bytes(first, second), plaintext_xor)


class FixAuthenticatedCookie(unittest.TestCase):
    def setUp(self):
        self.encryption_key = make_key()
        self.mac_key = make_key()

    def test_genuine_cookie_round_trips(self):
        cookie = seal(self.encryption_key, self.mac_key, USER_SESSION)
        self.assertEqual(open_sealed(self.encryption_key, self.mac_key, cookie), USER_SESSION)

    def test_bit_flipped_role_is_rejected(self):
        cookie = seal(self.encryption_key, self.mac_key, USER_SESSION)
        forged = flip_bytes(cookie, NONCE_BYTES + ROLE_OFFSET, b"user", b"root")
        with self.assertRaises(InvalidCookie):
            open_sealed(self.encryption_key, self.mac_key, forged)

    def test_any_single_bit_change_is_rejected(self):
        cookie = seal(self.encryption_key, self.mac_key, USER_SESSION)
        for byte_index in range(len(cookie)):
            edited = bytearray(cookie)
            edited[byte_index] ^= 0x01
            with self.assertRaises(InvalidCookie, msg=byte_index):
                open_sealed(self.encryption_key, self.mac_key, bytes(edited))

    def test_truncated_cookie_is_rejected(self):
        cookie = seal(self.encryption_key, self.mac_key, USER_SESSION)
        for length in (0, NONCE_BYTES, NONCE_BYTES + TAG_BYTES - 1, len(cookie) - 1):
            with self.assertRaises(InvalidCookie, msg=length):
                open_sealed(self.encryption_key, self.mac_key, cookie[:length])

    def test_cookie_from_another_mac_key_is_rejected(self):
        cookie = seal(self.encryption_key, make_key(), USER_SESSION)
        with self.assertRaises(InvalidCookie):
            open_sealed(self.encryption_key, self.mac_key, cookie)

    def test_same_session_encrypts_differently_each_time(self):
        first = seal(self.encryption_key, self.mac_key, USER_SESSION)
        second = seal(self.encryption_key, self.mac_key, USER_SESSION)
        self.assertNotEqual(first[NONCE_BYTES:-TAG_BYTES], second[NONCE_BYTES:-TAG_BYTES])

    def test_ciphertext_does_not_contain_the_plaintext(self):
        cookie = seal(self.encryption_key, self.mac_key, USER_SESSION)
        self.assertNotIn(b"role=user", cookie)

    def test_long_session_spanning_several_keystream_blocks_round_trips(self):
        session = {"uid": "1042", "role": "user", "cart": "x" * 200}
        cookie = seal(self.encryption_key, self.mac_key, session)
        self.assertEqual(open_sealed(self.encryption_key, self.mac_key, cookie), session)


if __name__ == "__main__":
    unittest.main()
