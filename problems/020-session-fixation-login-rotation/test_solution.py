import unittest

from solution import (
    LEVEL_ANONYMOUS,
    LEVEL_STEP_UP,
    LEVEL_USER,
    NaiveSessionManager,
    SessionManager,
)

VICTIM = "user-victim"


class SequentialIds:
    """Deterministic ID factory; can be told to repeat an ID to test collisions."""

    def __init__(self, ids: list[str]) -> None:
        self.ids = list(ids)

    def __call__(self) -> str:
        return self.ids.pop(0)


def attacker_planted_id() -> str:
    """An ID the attacker chose and pushed into the victim's browser."""
    return "attacker-" + "chosen-" + "id"


class ReproduceProblem(unittest.TestCase):
    def test_planted_id_becomes_logged_in_as_victim(self):
        manager = NaiveSessionManager()
        planted = attacker_planted_id()
        victim_cookie = manager.start(planted)        # victim's browser sends the planted ID
        manager.login(victim_cookie, VICTIM)
        self.assertEqual(manager.current_user(planted), VICTIM)

    def test_id_issued_before_login_stays_valid_after_login(self):
        manager = NaiveSessionManager()
        anonymous_id = manager.start(None)            # attacker grabs a real anonymous ID
        self.assertEqual(manager.login(anonymous_id, VICTIM), anonymous_id)
        self.assertEqual(manager.current_user(anonymous_id), VICTIM)


class FixRotation(unittest.TestCase):
    def setUp(self) -> None:
        self.manager = SessionManager()

    def test_unknown_client_id_is_not_adopted(self):
        issued = self.manager.start(attacker_planted_id())
        self.assertNotEqual(issued, attacker_planted_id())
        self.assertNotIn(attacker_planted_id(), self.manager.sessions)

    def test_login_issues_a_new_id(self):
        anonymous_id = self.manager.start(None)
        logged_in_id = self.manager.login(anonymous_id, VICTIM)
        self.assertNotEqual(logged_in_id, anonymous_id)
        self.assertEqual(self.manager.current_user(logged_in_id), VICTIM)

    def test_pre_login_id_is_worthless_after_login(self):
        anonymous_id = self.manager.start(None)
        self.manager.login(anonymous_id, VICTIM)
        self.assertIsNone(self.manager.current_user(anonymous_id))
        self.assertNotEqual(self.manager.start(anonymous_id), anonymous_id)

    def test_cart_survives_login(self):
        anonymous_id = self.manager.start(None)
        self.manager.sessions[anonymous_id].data["cart"] = ["sku-1"]
        logged_in_id = self.manager.login(anonymous_id, VICTIM)
        self.assertEqual(self.manager.sessions[logged_in_id].data, {"cart": ["sku-1"]})

    def test_switching_user_does_not_carry_previous_users_cart(self):
        alice_id = self.manager.login(self.manager.start(None), "alice")
        self.manager.sessions[alice_id].data["cart"] = ["private item"]
        bob_id = self.manager.login(alice_id, "bob")
        self.assertEqual(self.manager.current_user(bob_id), "bob")
        self.assertEqual(self.manager.sessions[bob_id].data, {})

    def test_same_user_logging_in_again_keeps_cart(self):
        alice_id = self.manager.login(self.manager.start(None), "alice")
        self.manager.sessions[alice_id].data["cart"] = ["sku-1"]
        again_id = self.manager.login(alice_id, "alice")
        self.assertEqual(self.manager.sessions[again_id].data, {"cart": ["sku-1"]})

    def test_step_up_rotates_and_raises_level(self):
        user_id = self.manager.login(self.manager.start(None), VICTIM)
        stepped_up_id = self.manager.step_up(user_id)
        self.assertNotEqual(stepped_up_id, user_id)
        self.assertEqual(self.manager.level(stepped_up_id), LEVEL_STEP_UP)
        self.assertEqual(self.manager.level(user_id), LEVEL_ANONYMOUS)

    def test_step_up_requires_login(self):
        with self.assertRaises(PermissionError):
            self.manager.step_up(self.manager.start(None))

    def test_logout_destroys_session_and_cart(self):
        user_id = self.manager.login(self.manager.start(None), VICTIM)
        self.manager.sessions[user_id].data["cart"] = ["sku-1"]
        fresh_id = self.manager.logout(user_id)
        self.assertIsNone(self.manager.current_user(user_id))
        self.assertEqual(self.manager.sessions[fresh_id].data, {})
        self.assertEqual(self.manager.level(fresh_id), LEVEL_ANONYMOUS)

    def test_login_with_unknown_session_is_refused(self):
        with self.assertRaises(KeyError):
            self.manager.login(attacker_planted_id(), VICTIM)

    def test_known_id_is_kept_between_requests(self):
        user_id = self.manager.login(self.manager.start(None), VICTIM)
        self.assertEqual(self.manager.start(user_id), user_id)
        self.assertEqual(self.manager.level(user_id), LEVEL_USER)


class FixIdGeneration(unittest.TestCase):
    def test_colliding_id_is_skipped(self):
        manager = SessionManager(id_factory=SequentialIds(["a", "a", "b"]))
        first = manager.start(None)
        second = manager.start(None)
        self.assertEqual((first, second), ("a", "b"))

    def test_default_ids_are_long_and_unique(self):
        manager = SessionManager()
        ids = {manager.start(None) for _ in range(1000)}
        self.assertEqual(len(ids), 1000)
        self.assertTrue(all(len(session_id) >= 43 for session_id in ids))


if __name__ == "__main__":
    unittest.main()
