import time
import unittest

from solution import MAX_EMAIL_LENGTH, is_valid_email, original_is_valid_email

SHORT_ATTACK_LENGTH = 16
LONGER_ATTACK_LENGTH = 20
# Four more characters should cost about 2**4 = 16x more; 4x leaves room for noise.
MIN_EXPECTED_SLOWDOWN = 4.0
FAST_ENOUGH_SECONDS = 0.05


def hostile_address(letter_count: int) -> str:
    """Many valid characters then one invalid one: the worst case for backtracking."""
    return "a" * letter_count + "!"


def seconds_to_run(validator, address: str) -> float:
    start = time.perf_counter()
    validator(address)
    return time.perf_counter() - start


class ReproduceProblem(unittest.TestCase):
    def test_original_accepts_a_normal_address(self):
        self.assertTrue(original_is_valid_email("asha.k+news@mail.example.in"))

    def test_original_work_grows_exponentially_with_input_length(self):
        short_time = seconds_to_run(original_is_valid_email, hostile_address(SHORT_ATTACK_LENGTH))
        longer_time = seconds_to_run(original_is_valid_email, hostile_address(LONGER_ATTACK_LENGTH))
        self.assertGreater(longer_time, short_time * MIN_EXPECTED_SLOWDOWN)


class FixAcceptsRealAddresses(unittest.TestCase):
    def test_simple_address_is_valid(self):
        self.assertTrue(is_valid_email("ravi@example.com"))

    def test_plus_tag_and_subdomain_are_valid(self):
        self.assertTrue(is_valid_email("asha.k+news@mail.example.in"))

    def test_hyphen_inside_domain_label_is_valid(self):
        self.assertTrue(is_valid_email("ops@my-shop.co.in"))


class FixRejectsBadAddresses(unittest.TestCase):
    def test_missing_at_sign_is_rejected(self):
        self.assertFalse(is_valid_email("ravi.example.com"))

    def test_two_at_signs_are_rejected(self):
        self.assertFalse(is_valid_email("ravi@@example.com"))

    def test_domain_without_dot_is_rejected(self):
        self.assertFalse(is_valid_email("ravi@localhost"))

    def test_consecutive_dots_in_local_part_are_rejected(self):
        self.assertFalse(is_valid_email("ravi..k@example.com"))

    def test_label_starting_with_hyphen_is_rejected(self):
        self.assertFalse(is_valid_email("ravi@-example.com"))

    def test_numeric_top_level_domain_is_rejected(self):
        self.assertFalse(is_valid_email("ravi@example.123"))

    def test_overlong_local_part_is_rejected(self):
        self.assertFalse(is_valid_email("a" * 65 + "@example.com"))

    def test_address_over_length_cap_is_rejected(self):
        long_domain = ".".join(["a" * 60] * 5) + ".com"
        self.assertGreater(len("x@" + long_domain), MAX_EMAIL_LENGTH)
        self.assertFalse(is_valid_email("x@" + long_domain))


class FixIsFastOnHostileInput(unittest.TestCase):
    def test_attack_that_slows_the_original_is_rejected_quickly(self):
        address = hostile_address(LONGER_ATTACK_LENGTH)
        self.assertFalse(is_valid_email(address))
        self.assertLess(seconds_to_run(is_valid_email, address), FAST_ENOUGH_SECONDS)

    def test_megabyte_input_is_rejected_quickly(self):
        address = hostile_address(1_000_000)
        self.assertLess(seconds_to_run(is_valid_email, address), FAST_ENOUGH_SECONDS)

    def test_worst_case_within_length_cap_is_fast(self):
        address = "a" * 64 + "@" + "b" * 63 + "." + "c" * 63 + "!"
        self.assertFalse(is_valid_email(address))
        self.assertLess(seconds_to_run(is_valid_email, address), FAST_ENOUGH_SECONDS)


if __name__ == "__main__":
    unittest.main()
