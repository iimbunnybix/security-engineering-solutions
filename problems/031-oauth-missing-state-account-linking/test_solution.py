import unittest

from solution import (STATE_LIFETIME_SECONDS, AccountStore, FakeIdentityProvider,
                      OAuthError, Session, original_link_callback, safe_link_callback,
                      start_link_flow)

START_TIME = 1_000.0


def make_store() -> AccountStore:
    return AccountStore(FakeIdentityProvider())


class ReproduceProblem(unittest.TestCase):
    def test_attacker_code_finished_in_victim_browser_takes_over_account(self):
        store = make_store()
        victim_session = Session(user_id="victim-17")
        # The attacker approves the consent screen with their own Google account
        # and keeps the callback URL instead of opening it.
        attacker_code = store.provider.authorize("google:attacker")
        # The victim opens the planted link while logged in.
        original_link_callback(store, victim_session, attacker_code)
        # Later the attacker signs in with Google and lands in the victim's account.
        fresh_code = store.provider.authorize("google:attacker")
        self.assertEqual(store.sign_in_with_provider(fresh_code), "victim-17")


class FixStateIsBoundToSession(unittest.TestCase):
    def setUp(self):
        self.store = make_store()
        self.victim_session = Session(user_id="victim-17")

    def test_legitimate_flow_links_the_users_own_identity(self):
        state = start_link_flow(self.victim_session, START_TIME)
        code = self.store.provider.authorize("google:victim")
        safe_link_callback(self.store, self.victim_session, code, state, START_TIME + 30)
        sign_in_code = self.store.provider.authorize("google:victim")
        self.assertEqual(self.store.sign_in_with_provider(sign_in_code), "victim-17")

    def test_callback_without_state_is_rejected(self):
        attacker_code = self.store.provider.authorize("google:attacker")
        with self.assertRaises(OAuthError):
            safe_link_callback(self.store, self.victim_session, attacker_code, None, START_TIME)
        self.assertNotIn("google:attacker", self.store.linked)

    def test_state_from_attackers_own_session_is_rejected(self):
        attacker_session = Session(user_id="attacker-99")
        attacker_state = start_link_flow(attacker_session, START_TIME)
        attacker_code = self.store.provider.authorize("google:attacker")
        with self.assertRaises(OAuthError):
            safe_link_callback(self.store, self.victim_session, attacker_code,
                               attacker_state, START_TIME + 5)
        self.assertNotIn("google:attacker", self.store.linked)

    def test_rejected_callback_does_not_exchange_the_code(self):
        attacker_code = self.store.provider.authorize("google:attacker")
        with self.assertRaises(OAuthError):
            safe_link_callback(self.store, self.victim_session, attacker_code,
                               "guessed-state", START_TIME)
        self.assertTrue(self.store.provider.has_unused_code(attacker_code))

    def test_attacker_code_with_victims_pending_state_cannot_be_planted_without_the_state(self):
        # The victim has a flow open, but the attacker cannot read its state value.
        start_link_flow(self.victim_session, START_TIME)
        attacker_code = self.store.provider.authorize("google:attacker")
        with self.assertRaises(OAuthError):
            safe_link_callback(self.store, self.victim_session, attacker_code,
                               "not-the-real-state", START_TIME + 1)

    def test_state_cannot_be_used_twice(self):
        state = start_link_flow(self.victim_session, START_TIME)
        first_code = self.store.provider.authorize("google:victim")
        safe_link_callback(self.store, self.victim_session, first_code, state, START_TIME + 1)
        second_code = self.store.provider.authorize("google:attacker")
        with self.assertRaises(OAuthError):
            safe_link_callback(self.store, self.victim_session, second_code, state, START_TIME + 2)

    def test_expired_state_is_rejected(self):
        state = start_link_flow(self.victim_session, START_TIME)
        code = self.store.provider.authorize("google:victim")
        with self.assertRaises(OAuthError):
            safe_link_callback(self.store, self.victim_session, code, state,
                               START_TIME + STATE_LIFETIME_SECONDS)

    def test_logged_out_session_cannot_start_or_finish_a_link(self):
        logged_out = Session(user_id=None)
        with self.assertRaises(OAuthError):
            start_link_flow(logged_out, START_TIME)
        code = self.store.provider.authorize("google:victim")
        with self.assertRaises(OAuthError):
            safe_link_callback(self.store, logged_out, code, "anything", START_TIME)

    def test_identity_linked_elsewhere_is_not_moved(self):
        self.store.link("google:shared", "other-user-5")
        state = start_link_flow(self.victim_session, START_TIME)
        code = self.store.provider.authorize("google:shared")
        with self.assertRaises(OAuthError):
            safe_link_callback(self.store, self.victim_session, code, state, START_TIME + 1)
        self.assertEqual(self.store.linked["google:shared"], "other-user-5")

    def test_two_tabs_can_each_finish_their_own_flow(self):
        first_state = start_link_flow(self.victim_session, START_TIME)
        second_state = start_link_flow(self.victim_session, START_TIME + 1)
        self.assertNotEqual(first_state, second_state)
        code = self.store.provider.authorize("google:victim")
        safe_link_callback(self.store, self.victim_session, code, second_state, START_TIME + 2)
        self.assertIn(first_state, self.victim_session.pending_oauth_states)

    def test_abandoned_states_are_cleaned_up(self):
        start_link_flow(self.victim_session, START_TIME)
        start_link_flow(self.victim_session, START_TIME + STATE_LIFETIME_SECONDS + 1)
        self.assertEqual(len(self.victim_session.pending_oauth_states), 1)


if __name__ == "__main__":
    unittest.main()
