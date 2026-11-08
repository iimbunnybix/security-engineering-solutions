import secrets
import unittest

from solution import (KEY_TAG, PREFIX_HEX_CHARS, SECRET_HEX_CHARS, HashedKeyStore,
                      NaiveKeyTable, build_key, keyed_hash, migrate_plaintext_table)


def make_pepper() -> bytes:
    """A fresh server-side pepper, built at runtime."""
    return secrets.token_bytes(32)


def random_secret() -> str:
    """A fresh secret part of a key, built at runtime."""
    return secrets.token_hex(SECRET_HEX_CHARS // 2)


class CountingComparator:
    """Records how many comparisons ran and delegates to a real equality check."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, left: bytes, right: bytes) -> bool:
        self.calls += 1
        return left == right


class ScriptedHex:
    """Fake randomness: returns the queued values in order, then real random hex."""

    def __init__(self, *values: str) -> None:
        self.values = list(values)

    def __call__(self, n_chars: int) -> str:
        if self.values:
            return self.values.pop(0)
        return secrets.token_hex(n_chars // 2)


class ReproduceProblem(unittest.TestCase):
    def test_leaked_dump_lets_attacker_use_every_customers_key(self):
        table = NaiveKeyTable()
        for customer in ["acme", "globex", "initech"]:
            table.create_key(customer)
        leaked = table.dump()
        used_as = [table.authenticate(row["key"]) for row in leaked]
        self.assertEqual(sorted(used_as), ["acme", "globex", "initech"])


class FixHashedKeysWithPepper(unittest.TestCase):
    def setUp(self):
        self.pepper = make_pepper()
        self.store = HashedKeyStore(self.pepper)
        self.issued = self.store.create_key("acme")

    def test_issued_key_authenticates(self):
        self.assertEqual(self.store.authenticate(self.issued.full_key), "acme")

    def test_issued_key_is_well_formed(self):
        tag, prefix, secret = self.issued.full_key.split("_")
        self.assertEqual(tag, KEY_TAG)
        self.assertEqual(len(prefix), PREFIX_HEX_CHARS)
        self.assertEqual(len(secret), SECRET_HEX_CHARS)

    def test_dump_contains_no_full_key(self):
        for row in self.store.dump():
            self.assertNotIn(self.issued.full_key, repr(row))
            self.assertNotIn(self.issued.full_key.split("_")[2], repr(row))

    def test_nothing_in_the_dump_authenticates(self):
        for row in self.store.dump():
            for candidate in [row.prefix, row.key_hmac.hex(),
                              build_key(row.prefix, row.key_hmac.hex())]:
                self.assertIsNone(self.store.authenticate(candidate))

    def test_dump_cannot_verify_guesses_without_the_pepper(self):
        row = self.store.dump()[0]
        guessed_pepper = make_pepper()
        # Even with the real key in hand, a wrong pepper does not reproduce the row.
        self.assertNotEqual(keyed_hash(guessed_pepper, self.issued.full_key), row.key_hmac)

    def test_wrong_secret_with_right_prefix_is_rejected(self):
        forged = build_key(self.issued.prefix, "0" * SECRET_HEX_CHARS)
        self.assertIsNone(self.store.authenticate(forged))

    def test_unknown_prefix_still_runs_one_comparison(self):
        known, unknown = CountingComparator(), CountingComparator()
        self.store.authenticate(build_key(self.issued.prefix, "0" * SECRET_HEX_CHARS), known)
        self.store.authenticate(build_key("f" * PREFIX_HEX_CHARS, "0" * SECRET_HEX_CHARS), unknown)
        self.assertEqual(known.calls, 1)
        self.assertEqual(unknown.calls, 1)

    def test_malformed_keys_are_rejected(self):
        for bad in ["", f"{KEY_TAG}_", "xx_" + self.issued.full_key[3:],
                    self.issued.full_key + "_extra", self.issued.full_key[:-1]]:
            self.assertIsNone(self.store.authenticate(bad), bad)

    def test_dashboard_shows_prefix_but_not_secret(self):
        shown = self.store.display_keys("acme")
        self.assertEqual(len(shown), 1)
        self.assertIn(self.issued.prefix, shown[0])
        self.assertNotIn(self.issued.full_key.split("_")[2], shown[0])

    def test_revoked_key_stops_working(self):
        self.assertTrue(self.store.revoke(self.issued.prefix))
        self.assertIsNone(self.store.authenticate(self.issued.full_key))

    def test_short_pepper_is_refused(self):
        with self.assertRaises(ValueError):
            HashedKeyStore(secrets.token_bytes(8))


class FixPrefixCollisions(unittest.TestCase):
    def test_colliding_prefix_is_regenerated_not_overwritten(self):
        shared_prefix = secrets.token_hex(PREFIX_HEX_CHARS // 2)
        # Queue: first key's prefix and secret, then the same prefix again.
        fake_hex = ScriptedHex(shared_prefix, random_secret(), shared_prefix)
        store = HashedKeyStore(make_pepper(), fake_hex)
        first = store.create_key("acme")
        second = store.create_key("globex")
        self.assertNotEqual(first.prefix, second.prefix)
        self.assertEqual(store.authenticate(first.full_key), "acme")
        self.assertEqual(store.authenticate(second.full_key), "globex")

    def test_endless_collisions_raise_instead_of_overwriting(self):
        shared_prefix = secrets.token_hex(PREFIX_HEX_CHARS // 2)
        fake_hex = ScriptedHex(shared_prefix, random_secret(), *[shared_prefix] * 10)
        store = HashedKeyStore(make_pepper(), fake_hex)
        first = store.create_key("acme")
        with self.assertRaises(RuntimeError):
            store.create_key("globex")
        self.assertEqual(store.authenticate(first.full_key), "acme")


class FixMigration(unittest.TestCase):
    def test_existing_keys_keep_working_and_plaintext_is_wiped(self):
        old_table = NaiveKeyTable()
        old_keys = {old_table.create_key(name): name for name in ["acme", "globex"]}
        store = HashedKeyStore(make_pepper())
        self.assertEqual(migrate_plaintext_table(old_table, store), 2)
        self.assertEqual(old_table.dump(), [])
        for full_key, customer in old_keys.items():
            self.assertEqual(store.authenticate(full_key), customer)

    def test_importing_a_malformed_key_raises(self):
        store = HashedKeyStore(make_pepper())
        with self.assertRaises(ValueError):
            store.import_plaintext_key("not-a-key", "acme")


if __name__ == "__main__":
    unittest.main()
