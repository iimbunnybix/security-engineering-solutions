import random
import unittest

from solution import (
    FREE_FAILURES,
    MAX_DELAY_SECONDS,
    FakeClock,
    LoginOutcome,
    ThrottledLoginService,
    backoff_delay,
    naive_login,
)

ACCOUNT_COUNT = 1000
REUSE_RATE = 0.02            # share of leaked pairs that still work on our site
ONE_HOUR = 60 * 60
ATTACKER_IP = "203.0.113.50"
OWNER_IP = "198.51.100.7"
SEED = 7


def build_site_and_leak() -> tuple[dict[str, str], list[tuple[str, str]]]:
    """Our users' passwords, and a leaked list from another site where 2% match."""
    rng = random.Random(SEED)
    passwords = {}
    leaked_pairs = []
    for index in range(ACCOUNT_COUNT):
        email = f"user{index}@example.com"
        passwords[email] = f"site-pw-{rng.random()}"
        if rng.random() < REUSE_RATE:
            leaked_pairs.append((email, passwords[email]))
        else:
            leaked_pairs.append((email, f"other-site-pw-{rng.random()}"))
    return passwords, leaked_pairs


def run_attack_for(service: ThrottledLoginService, clock: FakeClock,
                   leaked_pairs: list[tuple[str, str]], duration: float) -> tuple[int, int]:
    """Attacker on one IP tries pairs as fast as the throttle allows."""
    attempts = 0
    takeovers = 0
    start = clock.time()
    for email, password in leaked_pairs:
        result = service.login(email, password, ATTACKER_IP)
        if result.outcome == LoginOutcome.THROTTLED:
            clock.advance(result.retry_after_seconds)
            if clock.time() - start > duration:
                break
            result = service.login(email, password, ATTACKER_IP)
        attempts += 1
        if result.outcome == LoginOutcome.SUCCESS:
            takeovers += 1
    return attempts, takeovers


class ReproduceProblem(unittest.TestCase):
    def test_naive_login_lets_one_ip_try_every_leaked_pair(self):
        passwords, leaked_pairs = build_site_and_leak()
        takeovers = 0
        for email, password in leaked_pairs:
            if naive_login(passwords, email, password) == LoginOutcome.SUCCESS:
                takeovers += 1
        self.assertGreater(takeovers, 10)


class FixBackoffSchedule(unittest.TestCase):
    def test_first_failures_have_no_delay(self):
        self.assertEqual(backoff_delay(FREE_FAILURES - 1), 0.0)

    def test_delay_doubles_after_free_failures(self):
        self.assertEqual(backoff_delay(FREE_FAILURES), 1.0)
        self.assertEqual(backoff_delay(FREE_FAILURES + 3), 8.0)

    def test_delay_is_capped(self):
        self.assertEqual(backoff_delay(FREE_FAILURES + 50), MAX_DELAY_SECONDS)


class FixCredentialStuffing(unittest.TestCase):
    def setUp(self):
        self.passwords, self.leaked_pairs = build_site_and_leak()
        self.clock = FakeClock()
        self.service = ThrottledLoginService(self.passwords, self.clock)

    def test_one_ip_gets_only_a_handful_of_attempts_per_hour(self):
        attempts, takeovers = run_attack_for(self.service, self.clock, self.leaked_pairs, ONE_HOUR)
        self.assertLessEqual(attempts, 20)
        self.assertLessEqual(takeovers, 1)

    def test_throttled_request_does_not_check_the_password(self):
        for _ in range(FREE_FAILURES):
            self.service.login("user0@example.com", "guess", ATTACKER_IP)
        correct = self.passwords["user0@example.com"]
        result = self.service.login("user0@example.com", correct, ATTACKER_IP)
        self.assertEqual(result.outcome, LoginOutcome.THROTTLED)
        self.assertGreater(result.retry_after_seconds, 0)

    def test_many_ips_hammering_one_account_are_throttled_by_account(self):
        for index in range(FREE_FAILURES):
            self.service.login("user0@example.com", "guess", f"10.0.0.{index}")
        result = self.service.login("user0@example.com", "guess", "10.0.0.99")
        self.assertEqual(result.outcome, LoginOutcome.THROTTLED)


class FixInterleavedOwnAccountLogins(unittest.TestCase):
    def test_attacker_logging_into_own_account_is_still_throttled(self):
        passwords, leaked_pairs = build_site_and_leak()
        passwords["attacker@example.com"] = "attacker-own-pw"
        clock = FakeClock()
        service = ThrottledLoginService(passwords, clock)
        throttled = 0
        for index, (email, password) in enumerate(leaked_pairs):
            if service.login(email, password, ATTACKER_IP).outcome == LoginOutcome.THROTTLED:
                throttled += 1
            if index % (FREE_FAILURES - 1) == FREE_FAILURES - 2:
                service.login("attacker@example.com", "attacker-own-pw", ATTACKER_IP)
        self.assertGreater(throttled, len(leaked_pairs) - 2 * FREE_FAILURES)


class FixNoLockoutOfRealOwner(unittest.TestCase):
    def setUp(self):
        self.passwords, _ = build_site_and_leak()
        self.clock = FakeClock()
        self.service = ThrottledLoginService(self.passwords, self.clock)
        self.email = "user1@example.com"
        self.owner_password = self.passwords[self.email]

    def test_owner_on_known_ip_logs_in_while_attacker_is_throttled(self):
        self.service.login(self.email, self.owner_password, OWNER_IP)
        for _ in range(FREE_FAILURES + 3):
            self.service.login(self.email, "guess", ATTACKER_IP)
        result = self.service.login(self.email, self.owner_password, OWNER_IP)
        self.assertEqual(result.outcome, LoginOutcome.SUCCESS)

    def test_owner_on_new_ip_waits_at_most_the_cap(self):
        # A botnet guesses as fast as the account throttle allows, for hours.
        for index in range(FREE_FAILURES + 20):
            wait = self.service.login(self.email, "guess", f"10.0.1.{index}").retry_after_seconds
            self.clock.advance(wait)
            self.service.login(self.email, "guess", f"10.0.1.{index}")
        result = self.service.login(self.email, self.owner_password, OWNER_IP)
        self.assertEqual(result.outcome, LoginOutcome.THROTTLED)
        self.assertLessEqual(result.retry_after_seconds, MAX_DELAY_SECONDS)

    def test_success_resets_the_failure_count(self):
        for _ in range(FREE_FAILURES - 1):
            self.service.login(self.email, "typo", OWNER_IP)
        self.service.login(self.email, self.owner_password, OWNER_IP)
        for _ in range(FREE_FAILURES - 1):
            result = self.service.login(self.email, "typo", OWNER_IP)
        self.assertEqual(result.outcome, LoginOutcome.WRONG_PASSWORD)

    def test_success_on_own_account_does_not_clear_ip_failures_on_others(self):
        self.passwords["attacker@example.com"] = "attacker-own-pw"
        for index in range(FREE_FAILURES):
            self.service.login(f"user{index + 10}@example.com", "guess", ATTACKER_IP)
            self.service.login("attacker@example.com", "attacker-own-pw", ATTACKER_IP)
        result = self.service.login("user99@example.com", "guess", ATTACKER_IP)
        self.assertEqual(result.outcome, LoginOutcome.THROTTLED)

    def test_old_failures_are_forgotten_after_an_hour(self):
        for _ in range(FREE_FAILURES):
            self.service.login(self.email, "typo", OWNER_IP)
        self.clock.advance(ONE_HOUR + 1)
        self.service.login(self.email, "typo", OWNER_IP)
        result = self.service.login(self.email, self.owner_password, OWNER_IP)
        self.assertEqual(result.outcome, LoginOutcome.SUCCESS)


if __name__ == "__main__":
    unittest.main()
