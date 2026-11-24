import secrets
import unittest

from solution import (RESET_TOKEN_TTL_S, BadRequest, ResetRefused, UserCollection, complete_reset,
                      hash_password, naive_complete_reset, start_reset)

VICTIM = "victim@example.com"
ATTACKER = "attacker@example.com"
NEW_PASSWORD = "attacker-chose-this"


class FakeClock:
    def __init__(self, start=1_700_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_users():
    """Two accounts with random (test-only) original passwords."""
    return UserCollection([
        {"email": VICTIM, "password_hash": hash_password(secrets.token_hex(8)), "reset_token": None},
        {"email": ATTACKER, "password_hash": hash_password(secrets.token_hex(8)), "reset_token": None},
    ])


def reset_body(email, token, new_password=NEW_PASSWORD):
    return {"email": email, "token": token, "new_password": new_password}


def password_is(users, email, password):
    return users.find_one({"email": email})["password_hash"] == hash_password(password)


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.users, self.clock = make_users(), FakeClock()
        # The attacker clicks "forgot password" for the victim; the real token goes to the victim.
        start_reset(self.users, VICTIM, self.clock)

    def test_not_equal_operator_resets_the_victims_password(self):
        naive_complete_reset(self.users, reset_body(VICTIM, {"$ne": None}), self.clock)
        self.assertTrue(password_is(self.users, VICTIM, NEW_PASSWORD))

    def test_regex_operator_also_matches_any_token(self):
        naive_complete_reset(self.users, reset_body(VICTIM, {"$regex": "."}), self.clock)
        self.assertTrue(password_is(self.users, VICTIM, NEW_PASSWORD))

    def test_operator_in_email_takes_the_first_account_with_a_pending_reset(self):
        hijacked = naive_complete_reset(self.users, reset_body({"$gt": ""}, {"$ne": None}), self.clock)
        self.assertEqual(hijacked, VICTIM)


class FixTypedInputAndTokenCheck(unittest.TestCase):
    def setUp(self):
        self.users, self.clock = make_users(), FakeClock()
        self.token = start_reset(self.users, VICTIM, self.clock)

    def test_owner_with_the_real_token_can_reset(self):
        complete_reset(self.users, reset_body(VICTIM, self.token), self.clock)
        self.assertTrue(password_is(self.users, VICTIM, NEW_PASSWORD))

    def test_operator_object_as_token_is_a_bad_request(self):
        for operator in ({"$ne": None}, {"$regex": "."}, {"$gt": ""}):
            with self.subTest(operator=operator):
                with self.assertRaises(BadRequest):
                    complete_reset(self.users, reset_body(VICTIM, operator), self.clock)
        self.assertFalse(password_is(self.users, VICTIM, NEW_PASSWORD))

    def test_operator_object_as_email_is_a_bad_request(self):
        with self.assertRaises(BadRequest):
            complete_reset(self.users, reset_body({"$gt": ""}, self.token), self.clock)

    def test_list_value_is_a_bad_request(self):
        with self.assertRaises(BadRequest):
            complete_reset(self.users, reset_body(VICTIM, [self.token]), self.clock)

    def test_extra_or_missing_fields_are_a_bad_request(self):
        body = reset_body(VICTIM, self.token)
        body["role"] = "admin"
        with self.assertRaises(BadRequest):
            complete_reset(self.users, body, self.clock)
        with self.assertRaises(BadRequest):
            complete_reset(self.users, {"email": VICTIM, "token": self.token}, self.clock)

    def test_wrong_token_is_refused(self):
        with self.assertRaises(ResetRefused):
            complete_reset(self.users, reset_body(VICTIM, "not-the-token"), self.clock)

    def test_attackers_own_token_does_not_reset_the_victim(self):
        attacker_token = start_reset(self.users, ATTACKER, self.clock)
        with self.assertRaises(ResetRefused):
            complete_reset(self.users, reset_body(VICTIM, attacker_token), self.clock)

    def test_expired_token_is_refused(self):
        self.clock.advance(RESET_TOKEN_TTL_S)
        with self.assertRaises(ResetRefused):
            complete_reset(self.users, reset_body(VICTIM, self.token), self.clock)

    def test_token_works_only_once(self):
        complete_reset(self.users, reset_body(VICTIM, self.token), self.clock)
        with self.assertRaises(ResetRefused):
            complete_reset(self.users, reset_body(VICTIM, self.token, "second-password-123"), self.clock)

    def test_account_without_pending_reset_is_refused(self):
        with self.assertRaises(ResetRefused):
            complete_reset(self.users, reset_body(ATTACKER, "anything"), self.clock)

    def test_short_new_password_is_a_bad_request(self):
        with self.assertRaises(BadRequest):
            complete_reset(self.users, reset_body(VICTIM, self.token, "short"), self.clock)


if __name__ == "__main__":
    unittest.main()
