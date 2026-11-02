import hashlib
import unittest

from solution import UserStore, hash_password, needs_rehash, verify

FAST = 1_000          # low iteration count keeps tests quick


def sha1(p):
    return hashlib.sha1(p.encode()).hexdigest()


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.store = UserStore(iterations=FAST)
        self.store.hashes = {"asha": sha1("monsoon2024"), "ravi": sha1("chai&code")}

    def test_wrap_removes_all_raw_sha1_hashes(self):
        self.assertEqual(self.store.wrap_all_legacy(), 2)
        for h in self.store.hashes.values():
            self.assertTrue(h.startswith("wrapped$"))
            self.assertNotIn(sha1("monsoon2024"), h)

    def test_users_can_still_log_in_after_wrap(self):
        self.store.wrap_all_legacy()
        self.assertTrue(self.store.login("asha", "monsoon2024"))
        self.assertFalse(self.store.login("ravi", "wrong"))

    def test_login_upgrades_to_modern_hash(self):
        self.store.wrap_all_legacy()
        self.store.login("asha", "monsoon2024")
        self.assertTrue(self.store.hashes["asha"].startswith("pbkdf2_sha256$1000$"))
        self.assertTrue(self.store.login("asha", "monsoon2024"))
        self.assertTrue(self.store.hashes["ravi"].startswith("wrapped$"))   # untouched

    def test_failed_login_does_not_upgrade(self):
        self.store.wrap_all_legacy()
        before = self.store.hashes["ravi"]
        self.store.login("ravi", "guess")
        self.assertEqual(self.store.hashes["ravi"], before)

    def test_same_password_gets_different_hashes(self):
        self.assertNotEqual(hash_password("same", FAST), hash_password("same", FAST))

    def test_raising_iterations_triggers_rehash(self):
        old = hash_password("pw", 1_000)
        self.assertFalse(needs_rehash(old, 1_000))
        self.assertTrue(needs_rehash(old, 2_000))

    def test_unknown_user_and_garbage_hash(self):
        self.assertFalse(self.store.login("nobody", "x"))
        self.assertFalse(verify("x", "not-a-hash"))


if __name__ == "__main__":
    unittest.main()
