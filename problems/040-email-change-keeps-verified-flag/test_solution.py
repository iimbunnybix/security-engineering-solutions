import unittest

from solution import (Account, EmailVerifier, TOKEN_LIFETIME_SECONDS, VerificationError,
                      Workspace, auto_join, confirm_email, is_verified, naive_auto_join,
                      naive_change_email, request_email_change)

START = 1_000_000.0
VICTIM_DOMAIN = "victim-corp.test"
VICTIM_ADDRESS = f"cfo@{VICTIM_DOMAIN}"


def make_verified_attacker(verifier: EmailVerifier) -> Account:
    """An attacker who honestly verified his own mailbox first."""
    account = Account(user_id=66, email="eve@evil.test")
    token = verifier.issue(account, account.email, START)
    confirm_email(account, token, verifier, START)
    return account


class ReproduceProblem(unittest.TestCase):
    def test_verified_flag_survives_email_change_and_joins_victim_workspace(self):
        account = Account(user_id=66, email="eve@evil.test", email_verified=True)
        workspace = Workspace(VICTIM_DOMAIN)
        naive_change_email(account, VICTIM_ADDRESS)
        self.assertTrue(naive_auto_join(account, workspace))
        self.assertIn(66, workspace.members)


class FixVerificationBoundToAddress(unittest.TestCase):
    def setUp(self):
        self.verifier = EmailVerifier()
        self.workspace = Workspace(VICTIM_DOMAIN)

    def test_requested_change_keeps_old_address_until_confirmed(self):
        account = make_verified_attacker(self.verifier)
        request_email_change(account, VICTIM_ADDRESS, self.verifier, START)
        self.assertEqual(account.email, "eve@evil.test")
        self.assertFalse(auto_join(account, self.workspace))
        self.assertEqual(self.workspace.members, set())

    def test_email_changed_by_any_other_code_path_is_not_verified(self):
        account = make_verified_attacker(self.verifier)
        naive_change_email(account, VICTIM_ADDRESS)
        self.assertFalse(is_verified(account))
        self.assertFalse(auto_join(account, self.workspace))

    def test_token_from_new_inbox_completes_the_change(self):
        account = Account(user_id=7, email="asha@old.test")
        token = request_email_change(account, "Asha@Victim-Corp.test", self.verifier, START)
        confirm_email(account, token, self.verifier, START + 60)
        self.assertEqual(account.email, "asha@victim-corp.test")
        self.assertTrue(auto_join(account, self.workspace))

    def test_old_verification_token_cannot_confirm_a_new_address(self):
        account = Account(user_id=66, email="eve@evil.test")
        old_token = self.verifier.issue(account, account.email, START)
        request_email_change(account, VICTIM_ADDRESS, self.verifier, START)
        confirm_email(account, old_token, self.verifier, START)
        self.assertEqual(account.email, "eve@evil.test")
        self.assertFalse(auto_join(account, self.workspace))

    def test_token_cannot_be_used_twice(self):
        account = Account(user_id=7, email="asha@old.test")
        token = request_email_change(account, VICTIM_ADDRESS, self.verifier, START)
        confirm_email(account, token, self.verifier, START)
        with self.assertRaises(VerificationError):
            confirm_email(account, token, self.verifier, START)

    def test_expired_token_is_rejected(self):
        account = Account(user_id=7, email="asha@old.test")
        token = request_email_change(account, VICTIM_ADDRESS, self.verifier, START)
        with self.assertRaises(VerificationError):
            confirm_email(account, token, self.verifier, START + TOKEN_LIFETIME_SECONDS)
        self.assertEqual(account.email, "asha@old.test")

    def test_token_issued_for_another_account_is_rejected(self):
        victim = Account(user_id=1, email="asha@old.test")
        attacker = Account(user_id=66, email="eve@evil.test")
        token = request_email_change(victim, VICTIM_ADDRESS, self.verifier, START)
        attacker.pending_email = VICTIM_ADDRESS
        with self.assertRaises(VerificationError):
            confirm_email(attacker, token, self.verifier, START)

    def test_superseded_pending_request_cannot_be_confirmed(self):
        account = Account(user_id=7, email="asha@old.test")
        first = request_email_change(account, "typo@victim-corp.test", self.verifier, START)
        request_email_change(account, VICTIM_ADDRESS, self.verifier, START)
        with self.assertRaises(VerificationError):
            confirm_email(account, first, self.verifier, START)
        self.assertEqual(account.email, "asha@old.test")

    def test_unverified_account_on_domain_is_not_joined(self):
        account = Account(user_id=8, email=VICTIM_ADDRESS)
        self.assertFalse(auto_join(account, self.workspace))


if __name__ == "__main__":
    unittest.main()
