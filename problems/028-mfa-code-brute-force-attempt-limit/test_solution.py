import unittest

from solution import (
    ACCOUNT_FAILURE_WINDOW_S,
    CODE_SPACE,
    CODE_TTL_S,
    MAX_ACCOUNT_FAILURES,
    MAX_ATTEMPTS_PER_CHALLENGE,
    MfaVerifier,
    NaiveMfaVerifier,
    guess_probability,
)

SECRET_CODE = "734210"
WRONG_CODE = "000000"


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def fixed_code():
    return SECRET_CODE


def all_codes():
    for number in range(CODE_SPACE):
        yield f"{number:06d}"


class ReproduceProblem(unittest.TestCase):
    def test_attacker_enumerates_every_code_on_one_challenge(self):
        clock = FakeClock()
        naive = NaiveMfaVerifier(clock, make_code=fixed_code)
        challenge = naive.start("victim")
        attempts = 0
        for guess in all_codes():
            attempts += 1
            if naive.verify(challenge, guess):
                break
        self.assertEqual(attempts, int(SECRET_CODE) + 1)        # 734,211 guesses, then in

    def test_code_can_be_reused_after_success(self):
        naive = NaiveMfaVerifier(FakeClock(), make_code=fixed_code)
        challenge = naive.start("victim")
        self.assertTrue(naive.verify(challenge, SECRET_CODE))
        self.assertTrue(naive.verify(challenge, SECRET_CODE))


class GuessingMath(unittest.TestCase):
    def test_probability_is_guesses_over_one_million(self):
        self.assertEqual(guess_probability(1), 1 / 1_000_000)
        self.assertEqual(guess_probability(5), 0.000005)
        self.assertEqual(guess_probability(30_000), 0.03)
        self.assertEqual(guess_probability(2_000_000), 1.0)

    def test_naive_attacker_numbers_from_readme(self):
        # 100 guesses/s for the 5-minute validity window of one challenge.
        per_challenge = guess_probability(100 * CODE_TTL_S)
        self.assertEqual(per_challenge, 0.03)
        # Unlimited fresh challenges: 23 of them give better than even odds.
        self.assertAlmostEqual(1 - (1 - per_challenge) ** 23, 0.5037, places=4)

    def test_formula_matches_exhaustive_count(self):
        # For N distinct guesses, count how many of the 1,000,000 possible
        # secret codes would be hit. Guessing 000000..000004 hits exactly 5.
        guesses = {f"{number:06d}" for number in range(MAX_ATTEMPTS_PER_CHALLENGE)}
        hits = sum(1 for code in all_codes() if code in guesses)
        self.assertEqual(hits / CODE_SPACE, guess_probability(MAX_ATTEMPTS_PER_CHALLENGE))


class FixLimitsAttempts(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.mfa = MfaVerifier(self.clock, make_code=fixed_code)

    def fail(self, challenge, times):
        for _ in range(times):
            self.assertFalse(self.mfa.verify(challenge, WRONG_CODE))

    def test_correct_code_is_accepted(self):
        self.assertTrue(self.mfa.verify(self.mfa.start("victim"), SECRET_CODE))

    def test_code_is_single_use(self):
        challenge = self.mfa.start("victim")
        self.assertTrue(self.mfa.verify(challenge, SECRET_CODE))
        self.assertFalse(self.mfa.verify(challenge, SECRET_CODE))

    def test_correct_code_after_a_few_typos_is_accepted(self):
        challenge = self.mfa.start("victim")
        self.fail(challenge, MAX_ATTEMPTS_PER_CHALLENGE - 1)
        self.assertTrue(self.mfa.verify(challenge, SECRET_CODE))

    def test_challenge_is_destroyed_after_five_wrong_guesses(self):
        challenge = self.mfa.start("victim")
        self.fail(challenge, MAX_ATTEMPTS_PER_CHALLENGE)
        self.assertFalse(self.mfa.verify(challenge, SECRET_CODE))

    def test_expired_code_is_rejected(self):
        challenge = self.mfa.start("victim")
        self.clock.advance(CODE_TTL_S)
        self.assertFalse(self.mfa.verify(challenge, SECRET_CODE))

    def test_malformed_codes_are_rejected_and_counted(self):
        challenge = self.mfa.start("victim")
        for bad in ("", "73421", "7342100", "73421a", "٧٣٤٢١٠", " 734210"):
            self.assertFalse(self.mfa.verify(challenge, bad))
        self.assertFalse(self.mfa.verify(challenge, SECRET_CODE))    # 5 failures used it up

    def test_unknown_challenge_is_rejected(self):
        self.assertFalse(self.mfa.verify("no-such-challenge", SECRET_CODE))

    def test_new_challenges_do_not_reset_the_account_budget(self):
        for _ in range(MAX_ACCOUNT_FAILURES // MAX_ATTEMPTS_PER_CHALLENGE):
            self.fail(self.mfa.start("victim"), MAX_ATTEMPTS_PER_CHALLENGE)
        self.assertTrue(self.mfa.account_locked("victim"))
        with self.assertRaises(PermissionError):
            self.mfa.start("victim")

    def test_locked_account_rejects_even_the_right_code(self):
        first = self.mfa.start("victim")
        second = self.mfa.start("victim")
        self.fail(first, MAX_ATTEMPTS_PER_CHALLENGE)
        self.fail(second, MAX_ATTEMPTS_PER_CHALLENGE - 1)
        third = self.mfa.start("victim")
        self.fail(third, 1)                                     # 10th failure
        self.assertFalse(self.mfa.verify(second, SECRET_CODE))

    def test_lock_lifts_after_the_window(self):
        for _ in range(2):
            self.fail(self.mfa.start("victim"), MAX_ATTEMPTS_PER_CHALLENGE)
        self.clock.advance(ACCOUNT_FAILURE_WINDOW_S)
        self.assertFalse(self.mfa.account_locked("victim"))
        self.assertTrue(self.mfa.verify(self.mfa.start("victim"), SECRET_CODE))

    def test_other_accounts_are_not_affected(self):
        for _ in range(2):
            self.fail(self.mfa.start("victim"), MAX_ATTEMPTS_PER_CHALLENGE)
        self.assertTrue(self.mfa.verify(self.mfa.start("someone-else"), SECRET_CODE))

    def test_full_brute_force_gets_at_most_ten_guesses_per_day(self):
        guesses_made = 0
        codes = all_codes()
        while not self.mfa.account_locked("victim"):
            challenge = self.mfa.start("victim")
            for _ in range(MAX_ATTEMPTS_PER_CHALLENGE):
                guesses_made += 1
                self.assertFalse(self.mfa.verify(challenge, next(codes)))
        self.assertEqual(guesses_made, MAX_ACCOUNT_FAILURES)
        self.assertEqual(guess_probability(guesses_made), 0.00001)


if __name__ == "__main__":
    unittest.main()
