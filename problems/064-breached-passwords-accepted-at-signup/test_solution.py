import unittest

from solution import (
    HASH_PREFIX_LENGTH,
    FakeBreachRangeService,
    breach_count,
    check_new_password,
    naive_password_ok,
    sha1_hex,
)

# Passwords seen in (fake) breach dumps, with how many times each was seen.
LEAKED = {"Password1": 250_000, "Welcome@123": 40_000, "Summer2024!Summer": 12}
STRONG_UNLEAKED = "correct-horse-battery-staple-73"


def make_service():
    return FakeBreachRangeService(LEAKED)


class ReproduceProblem(unittest.TestCase):
    def test_top_leaked_passwords_pass_the_old_rules(self):
        self.assertTrue(naive_password_ok("Password1"))
        self.assertTrue(naive_password_ok("Welcome@123"))

    def test_long_passphrase_without_digit_fails_the_old_rules(self):
        self.assertFalse(naive_password_ok("correct horse battery staple"))


class FixRejectsBreachedPasswords(unittest.TestCase):
    def test_long_leaked_password_is_rejected_with_its_count(self):
        decision = check_new_password("Summer2024!Summer", "priya", make_service())
        self.assertFalse(decision.accepted)
        self.assertIn("12 data breaches", decision.reason)

    def test_unleaked_passphrase_is_accepted(self):
        decision = check_new_password(STRONG_UNLEAKED, "priya", make_service())
        self.assertEqual((decision.accepted, decision.breach_checked), (True, True))

    def test_short_password_is_rejected_before_any_lookup(self):
        service = make_service()
        decision = check_new_password("Password1", "priya", service)
        self.assertFalse(decision.accepted)
        self.assertEqual(service.queried_prefixes, [])

    def test_password_containing_username_is_rejected(self):
        decision = check_new_password("priya-loves-chai-2026", "Priya", make_service())
        self.assertFalse(decision.accepted)


class FixKAnonymity(unittest.TestCase):
    def test_only_a_five_character_hash_prefix_is_sent(self):
        service = make_service()
        check_new_password(STRONG_UNLEAKED, "priya", service)
        self.assertEqual(service.queried_prefixes, [sha1_hex(STRONG_UNLEAKED)[:HASH_PREFIX_LENGTH]])

    def test_match_is_found_by_comparing_the_suffix_locally(self):
        self.assertEqual(breach_count("Welcome@123", make_service()), 40_000)

    def test_unleaked_password_has_count_zero(self):
        self.assertEqual(breach_count(STRONG_UNLEAKED, make_service()), 0)


class FixServiceOutage(unittest.TestCase):
    def outage_service(self):
        service = make_service()
        service.available = False
        return service

    def test_common_password_is_still_rejected_during_outage(self):
        decision = check_new_password("Password1234", "priya", self.outage_service())
        self.assertFalse(decision.accepted)
        self.assertFalse(decision.breach_checked)

    def test_other_password_is_accepted_but_flagged_unchecked(self):
        decision = check_new_password(STRONG_UNLEAKED, "priya", self.outage_service())
        self.assertEqual((decision.accepted, decision.breach_checked), (True, False))


if __name__ == "__main__":
    unittest.main()
