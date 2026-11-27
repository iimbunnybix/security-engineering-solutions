import threading
import unittest

from solution import (TOKEN_LIFETIME_SECONDS, FakeClock, InvalidResetToken,
                      OriginalResetService, ResetService, UserStore, hash_token)

EMAIL = "priya@example.test"
OWNER_PASSWORD = "owner-new-password"
ATTACKER_PASSWORD = "attacker-password"
TEN_MINUTES = 10 * 60
CONCURRENT_SUBMISSIONS = 20


def make_users() -> UserStore:
    users = UserStore()
    users.set_password(EMAIL, "original-password")
    return users


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.users, self.clock = make_users(), FakeClock()
        self.service = OriginalResetService(self.users, self.clock)

    def test_link_from_history_resets_the_password_again_after_use(self):
        token = self.service.request_reset(EMAIL)
        self.service.reset_password(token, OWNER_PASSWORD)
        self.clock.advance(TEN_MINUTES)
        self.service.reset_password(token, ATTACKER_PASSWORD)
        self.assertTrue(self.users.check_password(EMAIL, ATTACKER_PASSWORD))
        self.assertFalse(self.users.check_password(EMAIL, OWNER_PASSWORD))

    def test_older_link_still_works_after_a_newer_one_was_used(self):
        old_token = self.service.request_reset(EMAIL)
        new_token = self.service.request_reset(EMAIL)
        self.service.reset_password(new_token, OWNER_PASSWORD)
        self.service.reset_password(old_token, ATTACKER_PASSWORD)
        self.assertTrue(self.users.check_password(EMAIL, ATTACKER_PASSWORD))

    def test_expiry_is_enforced_even_in_the_original(self):
        token = self.service.request_reset(EMAIL)
        self.clock.advance(TOKEN_LIFETIME_SECONDS)
        with self.assertRaises(InvalidResetToken):
            self.service.reset_password(token, OWNER_PASSWORD)


class FixSingleUseTokens(unittest.TestCase):
    def setUp(self):
        self.users, self.clock = make_users(), FakeClock()
        self.service = ResetService(self.users, self.clock)

    def test_first_use_sets_the_password(self):
        self.service.reset_password(self.service.request_reset(EMAIL), OWNER_PASSWORD)
        self.assertTrue(self.users.check_password(EMAIL, OWNER_PASSWORD))

    def test_second_use_of_the_same_link_is_refused(self):
        token = self.service.request_reset(EMAIL)
        self.service.reset_password(token, OWNER_PASSWORD)
        self.clock.advance(TEN_MINUTES)
        with self.assertRaises(InvalidResetToken):
            self.service.reset_password(token, ATTACKER_PASSWORD)
        self.assertTrue(self.users.check_password(EMAIL, OWNER_PASSWORD))

    def test_older_link_is_refused_after_a_newer_one_was_used(self):
        old_token = self.service.request_reset(EMAIL)
        self.service.reset_password(self.service.request_reset(EMAIL), OWNER_PASSWORD)
        with self.assertRaises(InvalidResetToken):
            self.service.reset_password(old_token, ATTACKER_PASSWORD)

    def test_logged_in_password_change_kills_outstanding_links(self):
        token = self.service.request_reset(EMAIL)
        self.service.change_password(EMAIL, "original-password", OWNER_PASSWORD)
        with self.assertRaises(InvalidResetToken):
            self.service.reset_password(token, ATTACKER_PASSWORD)

    def test_other_users_links_are_not_affected(self):
        self.users.set_password("other@example.test", "other-password")
        other_token = self.service.request_reset("other@example.test")
        self.service.reset_password(self.service.request_reset(EMAIL), OWNER_PASSWORD)
        self.service.reset_password(other_token, "other-new-password")
        self.assertTrue(self.users.check_password("other@example.test", "other-new-password"))

    def test_link_expires_after_one_hour(self):
        token = self.service.request_reset(EMAIL)
        self.clock.advance(TOKEN_LIFETIME_SECONDS)
        with self.assertRaises(InvalidResetToken):
            self.service.reset_password(token, OWNER_PASSWORD)

    def test_link_works_one_second_before_expiry(self):
        token = self.service.request_reset(EMAIL)
        self.clock.advance(TOKEN_LIFETIME_SECONDS - 1)
        self.service.reset_password(token, OWNER_PASSWORD)
        self.assertTrue(self.users.check_password(EMAIL, OWNER_PASSWORD))

    def test_too_short_password_does_not_use_up_the_link(self):
        token = self.service.request_reset(EMAIL)
        with self.assertRaises(ValueError):
            self.service.reset_password(token, "short")
        self.service.reset_password(token, OWNER_PASSWORD)
        self.assertTrue(self.users.check_password(EMAIL, OWNER_PASSWORD))

    def test_unknown_token_is_refused(self):
        with self.assertRaises(InvalidResetToken):
            self.service.reset_password("not-a-real-token", OWNER_PASSWORD)

    def test_only_the_hash_of_the_token_is_stored(self):
        token = self.service.request_reset(EMAIL)
        self.assertEqual(self.service.stored_token_hashes(), [hash_token(token)])
        self.assertNotIn(token, self.service.stored_token_hashes())


class FixConcurrentSubmissions(unittest.TestCase):
    def test_exactly_one_of_many_simultaneous_claims_succeeds(self):
        service = ResetService(make_users(), FakeClock())
        token = service.request_reset(EMAIL)
        start_together = threading.Barrier(CONCURRENT_SUBMISSIONS)
        winners = []

        def submit() -> None:
            start_together.wait()
            try:
                winners.append(service.claim_token(token))
            except InvalidResetToken:
                pass

        threads = [threading.Thread(target=submit) for _ in range(CONCURRENT_SUBMISSIONS)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(winners, [EMAIL])


if __name__ == "__main__":
    unittest.main()
