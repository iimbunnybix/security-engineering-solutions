import random
import unittest

from solution import (HEX_ALPHABET, SECRET_HEX_CHARS, HashedKeyStore, LeakyComparator,
                      digest_secret, generate_api_key, naive_authenticate,
                      recover_secret_by_timing, split_api_key)

SEED = 1505


def make_key() -> str:
    """Deterministic fake key built at runtime (never a literal in the file)."""
    return generate_api_key(random.Random(SEED))


def key_id_prefix(api_key: str) -> str:
    key_id, _secret = split_api_key(api_key)
    return f"sk_{key_id}_"


def naive_timing_oracle(stored_keys: dict[str, str]):
    """Work an attacker would observe for each guess against the original code."""
    def work_for_guess(guess: str) -> int:
        comparator = LeakyComparator()
        naive_authenticate(guess, stored_keys, comparator)
        return comparator.characters_examined
    return work_for_guess


def hashed_timing_oracle(store: HashedKeyStore):
    """Same measurement against the fix, even if the comparator were leaky."""
    def work_for_guess(guess: str) -> int:
        comparator = LeakyComparator()
        store.authenticate(guess, comparator)
        return comparator.characters_examined
    return work_for_guess


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.real_key = make_key()
        self.stored_keys = {self.real_key: "acme"}

    def test_longer_matching_prefix_takes_more_work(self):
        oracle = naive_timing_oracle(self.stored_keys)
        prefix = key_id_prefix(self.real_key)
        secret = split_api_key(self.real_key)[1]
        wrong_first = prefix + ("f" if secret[0] != "f" else "e") + "0" * (SECRET_HEX_CHARS - 1)
        right_first = prefix + secret[0] + "0" * (SECRET_HEX_CHARS - 1)
        self.assertGreater(oracle(right_first), oracle(wrong_first))

    def test_attacker_recovers_the_whole_secret_from_timing(self):
        prefix = key_id_prefix(self.real_key)
        recovered = recover_secret_by_timing(
            prefix, SECRET_HEX_CHARS, naive_timing_oracle(self.stored_keys),
            lambda guess: naive_authenticate(guess, self.stored_keys,
                                             LeakyComparator()) is not None)
        self.assertEqual(prefix + recovered, self.real_key)
        self.assertEqual(naive_authenticate(prefix + recovered, self.stored_keys,
                                            LeakyComparator()), "acme")

    def test_attack_needs_only_sixteen_guesses_per_character(self):
        guesses = []
        oracle = naive_timing_oracle(self.stored_keys)

        def counting_oracle(guess: str) -> int:
            guesses.append(guess)
            return oracle(guess)

        def counting_accept(guess: str) -> bool:
            guesses.append(guess)
            return naive_authenticate(guess, self.stored_keys, LeakyComparator()) is not None

        recover_secret_by_timing(key_id_prefix(self.real_key), SECRET_HEX_CHARS,
                                 counting_oracle, counting_accept)
        self.assertLessEqual(len(guesses), len(HEX_ALPHABET) * SECRET_HEX_CHARS)


class FixHashedConstantTimeKeys(unittest.TestCase):
    def setUp(self):
        self.real_key = make_key()
        self.store = HashedKeyStore()
        self.store.add_key(self.real_key, "acme")

    def test_valid_key_authenticates(self):
        self.assertEqual(self.store.authenticate(self.real_key), "acme")

    def test_wrong_secret_is_rejected(self):
        prefix = key_id_prefix(self.real_key)
        self.assertIsNone(self.store.authenticate(prefix + "0" * SECRET_HEX_CHARS))

    def test_timing_attack_fails_even_with_a_leaky_comparator(self):
        prefix = key_id_prefix(self.real_key)
        recovered = recover_secret_by_timing(
            prefix, SECRET_HEX_CHARS, hashed_timing_oracle(self.store),
            lambda guess: self.store.authenticate(guess) is not None)
        self.assertNotEqual(prefix + recovered, self.real_key)
        self.assertIsNone(self.store.authenticate(prefix + recovered))

    def test_unknown_key_id_does_the_same_comparison_work(self):
        _key_id, secret = split_api_key(self.real_key)
        wrong_secret = LeakyComparator()
        unknown_key_id = LeakyComparator()
        self.store.authenticate(key_id_prefix(self.real_key) + "0" * SECRET_HEX_CHARS,
                                wrong_secret)
        self.store.authenticate("sk_ffffffff_" + secret, unknown_key_id)
        self.assertEqual(wrong_secret.calls, 1)
        self.assertEqual(unknown_key_id.calls, 1)

    def test_correct_secret_with_unknown_key_id_is_rejected(self):
        _key_id, secret = split_api_key(self.real_key)
        self.assertIsNone(self.store.authenticate("sk_ffffffff_" + secret))

    def test_database_dump_contains_no_usable_key(self):
        _key_id, secret = split_api_key(self.real_key)
        dumped = self.store.stored_values()
        self.assertEqual(dumped, [digest_secret(secret)])
        self.assertNotIn(secret.encode(), b"".join(dumped))

    def test_malformed_keys_are_rejected_without_error(self):
        for bad in ["", "sk_", "sk_abc_def", "pk_12345678_" + "0" * SECRET_HEX_CHARS,
                    self.real_key + "_extra"]:
            self.assertIsNone(self.store.authenticate(bad), bad)

    def test_adding_a_malformed_key_raises(self):
        with self.assertRaises(ValueError):
            self.store.add_key("not-a-key", "acme")

    def test_generated_keys_are_unique_and_well_formed(self):
        first, second = generate_api_key(), generate_api_key()
        self.assertNotEqual(first, second)
        self.assertIsNotNone(split_api_key(first))


if __name__ == "__main__":
    unittest.main()
