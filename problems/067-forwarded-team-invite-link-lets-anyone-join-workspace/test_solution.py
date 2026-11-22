import unittest

from solution import (
    INVITE_TTL_SECONDS,
    Account,
    FakeClock,
    InviteError,
    InviteService,
    NaiveInviteService,
    hash_token,
)

WORKSPACE = "acme-roadmap"
INVITED = Account("u-asha", "asha@acme.example", email_verified=True)
OUTSIDER = Account("u-eve", "eve@elsewhere.example", email_verified=True)
SECOND_OUTSIDER = Account("u-mal", "mal@elsewhere.example", email_verified=True)


class ReproduceProblem(unittest.TestCase):
    def test_anyone_holding_a_forwarded_link_joins(self):
        service = NaiveInviteService()
        token = service.create_invite(WORKSPACE, INVITED.email)
        service.accept(token, OUTSIDER)
        self.assertIn(OUTSIDER.user_id, service.members[WORKSPACE])

    def test_one_link_lets_many_accounts_join(self):
        service = NaiveInviteService()
        token = service.create_invite(WORKSPACE, INVITED.email)
        for account in (INVITED, OUTSIDER, SECOND_OUTSIDER):
            service.accept(token, account)
        self.assertEqual(len(service.members[WORKSPACE]), 3)


class FixBindInviteToEmail(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.service = InviteService(self.clock)
        self.token = self.service.create_invite(WORKSPACE, INVITED.email)

    def assert_rejected(self, account, token=None):
        with self.assertRaises(InviteError):
            self.service.accept(token or self.token, account)

    def test_invited_person_joins(self):
        self.assertEqual(self.service.accept(self.token, INVITED), WORKSPACE)
        self.assertIn(INVITED.user_id, self.service.members[WORKSPACE])

    def test_outsider_with_the_link_is_rejected(self):
        self.assert_rejected(OUTSIDER)
        self.assertNotIn(WORKSPACE, self.service.members)

    def test_outsider_attempt_does_not_burn_the_invite(self):
        self.assert_rejected(OUTSIDER)
        self.assertEqual(self.service.accept(self.token, INVITED), WORKSPACE)

    def test_unverified_account_claiming_the_invited_email_is_rejected(self):
        squatter = Account("u-squat", INVITED.email, email_verified=False)
        self.assert_rejected(squatter)

    def test_email_case_and_spaces_do_not_matter(self):
        token = self.service.create_invite(WORKSPACE, " Ravi@Acme.Example ")
        ravi = Account("u-ravi", "ravi@acme.example", email_verified=True)
        self.assertEqual(self.service.accept(token, ravi), WORKSPACE)

    def test_invite_is_single_use(self):
        self.service.accept(self.token, INVITED)
        self.assert_rejected(INVITED)

    def test_expired_invite_is_rejected(self):
        self.clock.now += INVITE_TTL_SECONDS
        self.assert_rejected(INVITED)

    def test_invite_just_before_expiry_is_accepted(self):
        self.clock.now += INVITE_TTL_SECONDS - 1
        self.assertEqual(self.service.accept(self.token, INVITED), WORKSPACE)

    def test_revoked_invite_is_rejected(self):
        self.service.revoke(hash_token(self.token))
        self.assert_rejected(INVITED)

    def test_unknown_token_is_rejected(self):
        self.assert_rejected(INVITED, token="not-a-real-invite")

    def test_raw_token_is_not_stored(self):
        self.assertNotIn(self.token, self.service.invites)
        self.assertIn(hash_token(self.token), self.service.invites)


if __name__ == "__main__":
    unittest.main()
