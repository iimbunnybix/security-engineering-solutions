import hashlib
import hmac
import unittest

from solution import (BCRYPT_MAX_PASSWORD_BYTES, CURRENT_SCHEME, Account, bcrypt_like_kdf,
                      decode_hash, hash_password, login, naive_hash_password,
                      naive_verify_password, prehash_password, verify_password)

TENANT_ID = "0f6b2c1e-8a4d-4c7b-9e2f-3d5a6b7c8d9e"
LONG_EMAIL = "procurement.notifications@globex-industries.example"
SHORT_EMAIL = "ana@acme.example"
REAL_PASSWORD = "correct horse battery staple"
SHARED_PASSPHRASE_START = "my favourite line from the poem is: " * 2  # 72 ASCII bytes
FIXED_SALT = bytes(16)
NUL_SEARCH_LIMIT = 5000


def fake_pepper() -> bytes:
    """A deterministic fake pepper, built at runtime (never a real secret)."""
    return hashlib.sha256(b"test pepper for problem 049").digest()


def legacy_account(email: str, password: str) -> Account:
    """An account whose hash was made by the original code."""
    return Account(TENANT_ID, email, naive_hash_password(TENANT_ID, email, password))


def raw_digest_prehash(password: str, pepper: bytes) -> bytes:
    """A tempting but wrong pre-hash: the raw 32-byte digest, without base64."""
    return hmac.new(pepper, password.encode(), hashlib.sha256).digest()


def passwords_whose_raw_digest_starts_with_nul(pepper: bytes, wanted: int) -> list[str]:
    """Search candidate passwords for ones whose raw HMAC digest begins with 0x00."""
    found = []
    for index in range(NUL_SEARCH_LIMIT):
        candidate = f"candidate-password-{index}"
        if raw_digest_prehash(candidate, pepper)[0] == 0:
            found.append(candidate)
            if len(found) == wanted:
                break
    return found


class ReproduceProblem(unittest.TestCase):
    def test_long_email_prefix_fills_the_72_byte_window(self):
        prefix_length = len(f"{TENANT_ID}:{LONG_EMAIL}:".encode())
        self.assertGreaterEqual(prefix_length, BCRYPT_MAX_PASSWORD_BYTES)

    def test_any_password_matches_for_an_account_with_a_long_email(self):
        stored = naive_hash_password(TENANT_ID, LONG_EMAIL, REAL_PASSWORD)
        self.assertTrue(naive_verify_password(TENANT_ID, LONG_EMAIL, "x", stored))
        self.assertTrue(naive_verify_password(TENANT_ID, LONG_EMAIL, "", stored))

    def test_passphrases_sharing_the_first_72_bytes_collide(self):
        stored = naive_hash_password(TENANT_ID, SHORT_EMAIL, SHARED_PASSPHRASE_START + "alpha")
        other = SHARED_PASSPHRASE_START + "something else entirely"
        self.assertTrue(naive_verify_password(TENANT_ID, SHORT_EMAIL, other, stored))

    def test_short_email_account_still_rejects_a_wrong_password(self):
        stored = naive_hash_password(TENANT_ID, SHORT_EMAIL, REAL_PASSWORD)
        self.assertFalse(naive_verify_password(TENANT_ID, SHORT_EMAIL, "wrong", stored))

    def test_raw_digest_prehash_with_leading_nul_lets_passwords_collide(self):
        pepper = fake_pepper()
        first, second = passwords_whose_raw_digest_starts_with_nul(pepper, wanted=2)
        first_hash = bcrypt_like_kdf(raw_digest_prehash(first, pepper), FIXED_SALT)
        second_hash = bcrypt_like_kdf(raw_digest_prehash(second, pepper), FIXED_SALT)
        self.assertEqual(first_hash, second_hash)


class FixPrehashWithHmac(unittest.TestCase):
    def test_correct_password_verifies(self):
        stored = hash_password(REAL_PASSWORD, fake_pepper())
        self.assertTrue(verify_password(REAL_PASSWORD, stored, fake_pepper()))

    def test_wrong_password_is_rejected(self):
        stored = hash_password(REAL_PASSWORD, fake_pepper())
        self.assertFalse(verify_password("x", stored, fake_pepper()))

    def test_passphrases_sharing_the_first_72_bytes_no_longer_collide(self):
        stored = hash_password(SHARED_PASSPHRASE_START + "alpha", fake_pepper())
        other = SHARED_PASSPHRASE_START + "something else entirely"
        self.assertFalse(verify_password(other, stored, fake_pepper()))

    def test_long_multibyte_passwords_differing_only_at_the_end_are_distinct(self):
        base = "пароль" * 10  # 120 bytes of UTF-8
        stored = hash_password(base + "A", fake_pepper())
        self.assertFalse(verify_password(base + "B", stored, fake_pepper()))

    def test_prehash_is_short_and_has_no_nul_bytes(self):
        pepper = fake_pepper()
        for candidate in passwords_whose_raw_digest_starts_with_nul(pepper, wanted=3):
            prehashed = prehash_password(candidate, pepper)
            self.assertNotIn(b"\0", prehashed)
            self.assertLessEqual(len(prehashed), BCRYPT_MAX_PASSWORD_BYTES)

    def test_wrong_pepper_is_rejected(self):
        stored = hash_password(REAL_PASSWORD, fake_pepper())
        self.assertFalse(verify_password(REAL_PASSWORD, stored, b"another pepper"))

    def test_same_password_gets_a_different_salt_each_time(self):
        first = hash_password(REAL_PASSWORD, fake_pepper())
        second = hash_password(REAL_PASSWORD, fake_pepper())
        self.assertNotEqual(first, second)


class FixMigrateLegacyHashes(unittest.TestCase):
    def test_legacy_account_is_upgraded_on_correct_login(self):
        account = legacy_account(SHORT_EMAIL, REAL_PASSWORD)
        self.assertTrue(login(account, REAL_PASSWORD, fake_pepper()))
        scheme, _, _ = decode_hash(account.password_hash)
        self.assertEqual(scheme, CURRENT_SCHEME)

    def test_upgraded_account_rejects_a_wrong_password(self):
        account = legacy_account(SHORT_EMAIL, REAL_PASSWORD)
        login(account, REAL_PASSWORD, fake_pepper())
        self.assertFalse(login(account, "wrong", fake_pepper()))
        self.assertTrue(login(account, REAL_PASSWORD, fake_pepper()))

    def test_wrong_password_on_legacy_account_does_not_upgrade(self):
        account = legacy_account(SHORT_EMAIL, REAL_PASSWORD)
        original_hash = account.password_hash
        self.assertFalse(login(account, "wrong", fake_pepper()))
        self.assertEqual(account.password_hash, original_hash)

    def test_legacy_account_with_long_prefix_rejects_any_password(self):
        account = legacy_account(LONG_EMAIL, REAL_PASSWORD)
        self.assertFalse(login(account, "x", fake_pepper()))
        self.assertFalse(login(account, REAL_PASSWORD, fake_pepper()))

    def test_legacy_account_with_long_prefix_is_flagged_for_reset(self):
        account = legacy_account(LONG_EMAIL, REAL_PASSWORD)
        login(account, "x", fake_pepper())
        self.assertTrue(account.reset_required)


if __name__ == "__main__":
    unittest.main()
