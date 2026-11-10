import secrets
import unittest

from solution import (TIME_STEP_SECONDS, NaiveTotpVerifier, TotpVerifier, hotp,
                      time_step)

START_TIME = 1_700_000_010   # 10 seconds into a 30-second step
USER = "user-42"
OTHER_USER = "user-77"


class FakeClock:
    def __init__(self, now: float = START_TIME) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def code_at(secret: bytes, unix_time: float) -> str:
    """What the user's authenticator app shows at a given moment."""
    return hotp(secret, time_step(unix_time))


def wrong_code(correct_code: str) -> str:
    """A well-formed code guaranteed to differ from the correct one."""
    last_digit = (int(correct_code[-1]) + 1) % 10
    return correct_code[:-1] + str(last_digit)


class Rfc4226Vectors(unittest.TestCase):
    def test_hotp_matches_published_test_vectors(self):
        # RFC 4226 Appendix D uses the ASCII secret "1234567890" repeated twice.
        secret = b"1234567890" * 2
        expected = ["755224", "287082", "359152", "969429", "338314"]
        for counter, code in enumerate(expected):
            self.assertEqual(hotp(secret, counter), code)


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.secret = secrets.token_bytes(20)
        self.verifier = NaiveTotpVerifier({USER: self.secret}, self.clock)

    def test_valid_code_is_accepted(self):
        self.assertTrue(self.verifier.verify(USER, code_at(self.secret, self.clock())))

    def test_captured_code_is_accepted_again_for_the_attacker(self):
        code = code_at(self.secret, self.clock())
        self.verifier.verify(USER, code)
        self.clock.advance(20)
        self.assertTrue(self.verifier.verify(USER, code))

    def test_captured_code_works_until_end_of_next_step(self):
        code = code_at(self.secret, self.clock())
        self.verifier.verify(USER, code)
        # Step start + 59 s is still inside the "one step later" drift window.
        self.clock.advance(TIME_STEP_SECONDS * 2 - 10 - 1)
        self.assertTrue(self.verifier.verify(USER, code))


class FixRejectsReplay(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.secret = secrets.token_bytes(20)
        self.other_secret = secrets.token_bytes(20)
        self.verifier = TotpVerifier(
            {USER: self.secret, OTHER_USER: self.other_secret}, self.clock)

    def test_valid_code_is_accepted_once(self):
        self.assertTrue(self.verifier.verify(USER, code_at(self.secret, self.clock())))

    def test_same_code_is_rejected_the_second_time(self):
        code = code_at(self.secret, self.clock())
        self.verifier.verify(USER, code)
        self.clock.advance(5)
        self.assertFalse(self.verifier.verify(USER, code))

    def test_next_steps_code_is_accepted_after_using_one(self):
        self.verifier.verify(USER, code_at(self.secret, self.clock()))
        self.clock.advance(TIME_STEP_SECONDS)
        self.assertTrue(self.verifier.verify(USER, code_at(self.secret, self.clock())))

    def test_older_drift_code_is_rejected_after_newer_one_was_used(self):
        previous_code = code_at(self.secret, self.clock() - TIME_STEP_SECONDS)
        self.verifier.verify(USER, code_at(self.secret, self.clock()))
        self.assertFalse(self.verifier.verify(USER, previous_code))

    def test_code_from_slow_phone_is_still_accepted(self):
        slow_phone_code = code_at(self.secret, self.clock() - TIME_STEP_SECONDS)
        self.assertTrue(self.verifier.verify(USER, slow_phone_code))

    def test_code_older_than_drift_window_is_rejected(self):
        stale_code = code_at(self.secret, self.clock() - 2 * TIME_STEP_SECONDS)
        self.assertFalse(self.verifier.verify(USER, stale_code))

    def test_one_users_login_does_not_block_another_user(self):
        self.verifier.verify(USER, code_at(self.secret, self.clock()))
        self.assertTrue(self.verifier.verify(OTHER_USER, code_at(self.other_secret, self.clock())))

    def test_failed_attempt_does_not_burn_the_current_code(self):
        self.verifier.verify(USER, wrong_code(code_at(self.secret, self.clock())))
        self.assertTrue(self.verifier.verify(USER, code_at(self.secret, self.clock())))

    def test_malformed_codes_are_rejected(self):
        for code in ["", "12345", "1234567", "abcdef", "²²²²²²"]:
            with self.subTest(code=code):
                self.assertFalse(self.verifier.verify(USER, code))


if __name__ == "__main__":
    unittest.main()
