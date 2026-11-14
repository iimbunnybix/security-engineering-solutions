import unittest

from solution import (Account, Outbox, build_email_index, email_lookup_key,
                      naive_request_reset, request_reset)

VICTIM_EMAIL = "mike@github.test"
DOTLESS_I = "ı"          # "ı", upper-cases to plain "I"
KELVIN_SIGN = "K"        # "K", lower-cases to plain "k"
ATTACKER_EMAIL = "mike@g" + DOTLESS_I + "thub.test"


def victim_accounts() -> list[Account]:
    return [Account(user_id=1, email=VICTIM_EMAIL), Account(user_id=2, email="asha@example.test")]


def recipients(outbox: Outbox) -> list[str]:
    return [recipient for recipient, _token in outbox.sent]


class ReproduceProblem(unittest.TestCase):
    def test_dotless_i_lookalike_matches_victim_with_upper(self):
        self.assertEqual(ATTACKER_EMAIL.upper(), VICTIM_EMAIL.upper())

    def test_reset_link_for_victim_is_sent_to_attacker(self):
        outbox = Outbox()
        naive_request_reset(victim_accounts(), ATTACKER_EMAIL, outbox)
        self.assertEqual(recipients(outbox), [ATTACKER_EMAIL])


class FixLookupKey(unittest.TestCase):
    def test_dotless_i_lookalike_gets_a_different_key(self):
        self.assertNotEqual(email_lookup_key(ATTACKER_EMAIL), email_lookup_key(VICTIM_EMAIL))

    def test_plain_case_difference_still_matches(self):
        self.assertEqual(email_lookup_key("Mike@GitHub.TEST"), email_lookup_key(VICTIM_EMAIL))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(email_lookup_key("  mike@github.test "), email_lookup_key(VICTIM_EMAIL))


class FixResetDelivery(unittest.TestCase):
    def setUp(self) -> None:
        self.outbox = Outbox()
        self.index = build_email_index(victim_accounts())

    def test_lookalike_email_sends_nothing(self):
        request_reset(self.index, ATTACKER_EMAIL, self.outbox)
        self.assertEqual(self.outbox.sent, [])

    def test_link_goes_to_stored_address_not_typed_spelling(self):
        request_reset(self.index, "MIKE@GitHub.test", self.outbox)
        self.assertEqual(recipients(self.outbox), [VICTIM_EMAIL])

    def test_kelvin_sign_match_still_mails_only_the_stored_address(self):
        # NFKC folds the Kelvin sign to "K", so this matches; the link must
        # still go to the owner's real mailbox, never to the typed string.
        accounts = [Account(user_id=3, email="kim@example.test")]
        typed = KELVIN_SIGN + "im@example.test"
        request_reset(build_email_index(accounts), typed, self.outbox)
        self.assertEqual(recipients(self.outbox), ["kim@example.test"])

    def test_unknown_email_sends_nothing(self):
        request_reset(self.index, "nobody@example.test", self.outbox)
        self.assertEqual(self.outbox.sent, [])

    def test_each_reset_gets_a_fresh_token(self):
        request_reset(self.index, VICTIM_EMAIL, self.outbox)
        request_reset(self.index, VICTIM_EMAIL, self.outbox)
        first_token, second_token = [token for _recipient, token in self.outbox.sent]
        self.assertNotEqual(first_token, second_token)

    def test_accounts_sharing_a_key_are_refused(self):
        clashing = [Account(1, "Ann@example.test"), Account(2, "ann@example.test")]
        with self.assertRaises(ValueError):
            build_email_index(clashing)


if __name__ == "__main__":
    unittest.main()
