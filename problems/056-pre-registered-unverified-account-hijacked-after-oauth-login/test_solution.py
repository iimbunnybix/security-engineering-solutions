import unittest

from solution import (
    AccountStore,
    LinkRefused,
    OAuthIdentity,
    naive_oauth_login,
    oauth_login,
)

VICTIM_EMAIL = "priya@mail.example"


def attacker_password() -> str:
    return "attacker-" + "chosen-" + "passphrase"


def victim_password() -> str:
    return "victim-" + "own-" + "passphrase"


def google_identity(email: str = VICTIM_EMAIL, verified: bool = True,
                    subject: str = "google-sub-1001") -> OAuthIdentity:
    return OAuthIdentity(provider="google", subject=subject, email=email, email_verified=verified)


def store_with_attacker_pre_registration() -> tuple[AccountStore, str]:
    """The attacker signs up with the victim's email and never verifies it."""
    store = AccountStore()
    attacker_session = store.signup_with_password(VICTIM_EMAIL, attacker_password())
    return store, attacker_session


class ReproduceProblem(unittest.TestCase):
    def test_attacker_password_still_works_after_victim_signs_in_with_google(self):
        store, _ = store_with_attacker_pre_registration()
        naive_oauth_login(store, google_identity())
        self.assertIsNotNone(store.login_with_password(VICTIM_EMAIL, attacker_password()))

    def test_attacker_session_sees_the_victims_account(self):
        store, attacker_session = store_with_attacker_pre_registration()
        victim_session = naive_oauth_login(store, google_identity())
        self.assertIs(store.account_for_session(attacker_session),
                      store.account_for_session(victim_session))


class FixCleansUnverifiedAccount(unittest.TestCase):
    def test_attacker_password_no_longer_logs_in(self):
        store, _ = store_with_attacker_pre_registration()
        oauth_login(store, google_identity())
        self.assertIsNone(store.login_with_password(VICTIM_EMAIL, attacker_password()))

    def test_attacker_session_is_revoked(self):
        store, attacker_session = store_with_attacker_pre_registration()
        oauth_login(store, google_identity())
        self.assertIsNone(store.account_for_session(attacker_session))

    def test_victim_gets_a_working_session_and_verified_email(self):
        store, _ = store_with_attacker_pre_registration()
        victim_session = oauth_login(store, google_identity())
        account = store.account_for_session(victim_session)
        self.assertEqual(account.email, VICTIM_EMAIL)
        self.assertTrue(account.email_verified)

    def test_unverified_provider_email_is_not_linked(self):
        store, attacker_session = store_with_attacker_pre_registration()
        with self.assertRaises(LinkRefused):
            oauth_login(store, google_identity(verified=False))
        self.assertEqual(store.accounts[VICTIM_EMAIL].linked_identities, set())

    def test_email_matching_ignores_case(self):
        store, _ = store_with_attacker_pre_registration()
        oauth_login(store, google_identity(email="Priya@Mail.Example"))
        self.assertIsNone(store.login_with_password(VICTIM_EMAIL, attacker_password()))


class FixKeepsLegitimateAccountsIntact(unittest.TestCase):
    def test_verified_password_account_keeps_password_and_sessions(self):
        store = AccountStore()
        existing_session = store.signup_with_password(VICTIM_EMAIL, victim_password())
        store.mark_email_verified(VICTIM_EMAIL)
        oauth_login(store, google_identity())
        self.assertIsNotNone(store.login_with_password(VICTIM_EMAIL, victim_password()))
        self.assertIsNotNone(store.account_for_session(existing_session))

    def test_new_email_creates_a_linked_account(self):
        store = AccountStore()
        session = oauth_login(store, google_identity(email="new@mail.example"))
        account = store.account_for_session(session)
        self.assertIn(("google", "google-sub-1001"), account.linked_identities)

    def test_second_login_uses_the_existing_link_and_keeps_sessions(self):
        store, _ = store_with_attacker_pre_registration()
        first_session = oauth_login(store, google_identity())
        second_session = oauth_login(store, google_identity())
        self.assertIsNotNone(store.account_for_session(first_session))
        self.assertIs(store.account_for_session(first_session),
                      store.account_for_session(second_session))

    def test_attacker_cannot_sign_up_again_over_the_linked_account(self):
        store, _ = store_with_attacker_pre_registration()
        oauth_login(store, google_identity())
        with self.assertRaises(ValueError):
            store.signup_with_password(VICTIM_EMAIL, attacker_password())

    def test_wrong_password_is_rejected(self):
        store = AccountStore()
        store.signup_with_password(VICTIM_EMAIL, victim_password())
        self.assertIsNone(store.login_with_password(VICTIM_EMAIL, attacker_password()))


if __name__ == "__main__":
    unittest.main()
