import hashlib
import unittest
from unittest import mock

import solution

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


class FixUnknownUserTiming(unittest.TestCase):
    """Issue #1: unknown users must cost the same PBKDF2 work as wrong passwords."""

    def count_pbkdf2_calls_during_login(self, store: UserStore, user: str) -> int:
        with mock.patch.object(solution, "_pbkdf2", wraps=solution._pbkdf2) as counter:
            store.login(user, "wrong-password")
        return counter.call_count

    def test_unknown_user_does_same_hashing_work_as_wrong_password(self):
        store = UserStore(iterations=FAST)
        store.hashes = {"asha": hash_password("monsoon2024", FAST)}
        known_calls = self.count_pbkdf2_calls_during_login(store, "asha")
        unknown_calls = self.count_pbkdf2_calls_during_login(store, "nobody")
        self.assertEqual(known_calls, 1)
        self.assertEqual(unknown_calls, known_calls)


class FixMalformedStoredHash(unittest.TestCase):
    """Issue #2: a corrupted stored hash must fail closed, not raise."""

    def test_non_numeric_iteration_count_is_rejected(self):
        self.assertFalse(verify("x", "pbkdf2_sha256$abc$AAAA$AAAA"))

    def test_zero_iterations_is_rejected(self):
        self.assertFalse(verify("x", "pbkdf2_sha256$0$AAAA$AAAA"))

    def test_invalid_base64_is_rejected(self):
        self.assertFalse(verify("x", "wrapped$1000$***$AAAA"))

    def test_malformed_hash_needs_rehash(self):
        self.assertTrue(needs_rehash("pbkdf2_sha256$abc$AAAA$AAAA", FAST))

    def test_login_with_corrupted_row_returns_false(self):
        store = UserStore(iterations=FAST)
        store.hashes = {"asha": "pbkdf2_sha256$abc$AAAA$AAAA"}
        self.assertFalse(store.login("asha", "monsoon2024"))


if __name__ == "__main__":
    unittest.main()
