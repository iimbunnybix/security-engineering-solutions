import unittest

from solution import NaiveResetService, ResetTokenService, guess_naive_token

VICTIM = "victim@example.com"


class Clock:
    def __init__(self, t=1_790_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class ReproducePredictableTokens(unittest.TestCase):
    def test_attacker_guesses_token_from_request_time(self):
        clock = Clock()
        svc = NaiveResetService(clock)
        attacker_saw = clock() - 2.4          # attacker's clock / network delay is off
        clock.t += 0.7
        real = svc.request_reset(VICTIM)      # emailed to the victim, not the attacker
        found = guess_naive_token(svc, VICTIM, attacker_saw)
        self.assertIsNotNone(found)
        token, attempts = found
        self.assertEqual(token, real)
        self.assertLessEqual(attempts, 11)    # a few guesses, no rate limit can save it

    def test_tokens_never_expire_and_are_reusable(self):
        clock = Clock()
        svc = NaiveResetService(clock)
        token = svc.request_reset(VICTIM)
        clock.t += 90 * 24 * 3600
        self.assertEqual(svc.redeem(token), VICTIM)
        self.assertEqual(svc.redeem(token), VICTIM)

    def test_database_holds_working_tokens(self):
        svc = NaiveResetService(Clock())
        svc.request_reset(VICTIM)
        leaked = next(iter(svc.tokens))       # what a DB dump exposes
        self.assertEqual(svc.redeem(leaked), VICTIM)


class SecureTokens(unittest.TestCase):
    def test_tokens_are_long_and_unrelated_to_time_or_user(self):
        clock = Clock()
        svc = ResetTokenService(clock)
        a = svc.request_reset("u1")
        b = ResetTokenService(clock).request_reset("u1")   # same user, same second
        self.assertNotEqual(a, b)
        self.assertGreaterEqual(len(a), 43)               # 32 bytes base64url
        self.assertNotIn("u1", a)

    def test_time_guessing_attack_fails(self):
        clock = Clock()
        svc = ResetTokenService(clock)
        svc.request_reset(VICTIM)
        for delta in range(-30, 31):
            guess = NaiveResetService.make_token(VICTIM, int(clock()) + delta)
            self.assertIsNone(svc.redeem(guess))

    def test_valid_token_redeems_once(self):
        svc = ResetTokenService(Clock())
        token = svc.request_reset("u1")
        self.assertEqual(svc.redeem(token), "u1")
        self.assertIsNone(svc.redeem(token))

    def test_token_expires(self):
        clock = Clock()
        svc = ResetTokenService(clock)
        token = svc.request_reset("u1")
        clock.t += 30 * 60 - 1
        self.assertEqual(svc.redeem(token), "u1")
        token = svc.request_reset("u1")
        clock.t += 30 * 60
        self.assertIsNone(svc.redeem(token))

    def test_new_request_invalidates_previous_token(self):
        svc = ResetTokenService(Clock())
        first = svc.request_reset("u1")
        second = svc.request_reset("u1")
        self.assertIsNone(svc.redeem(first))
        self.assertEqual(svc.redeem(second), "u1")

    def test_other_users_tokens_unaffected(self):
        svc = ResetTokenService(Clock())
        t1 = svc.request_reset("u1")
        svc.request_reset("u2")
        self.assertEqual(svc.redeem(t1), "u1")

    def test_database_dump_contains_only_hashes(self):
        svc = ResetTokenService(Clock())
        token = svc.request_reset("u1")
        dumped = svc.stored_hashes()
        self.assertEqual(len(dumped), 1)
        self.assertNotIn(token.encode(), dumped)
        self.assertIsNone(svc.redeem(dumped[0].hex()))     # hash is not a usable token
        self.assertEqual(svc.redeem(token), "u1")

    def test_malformed_input(self):
        svc = ResetTokenService(Clock())
        svc.request_reset("u1")
        for bad in ["", "short", "x" * 500, None, 12345]:
            self.assertIsNone(svc.redeem(bad))


if __name__ == "__main__":
    unittest.main()
