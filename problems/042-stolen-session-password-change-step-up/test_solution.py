import secrets
import unittest

from solution import (MAX_REAUTH_FAILURES, REAUTH_WINDOW_SECONDS, Account, SessionRevoked,
                      StepUpRequired, change_email, change_password, disable_mfa,
                      hash_password, log_in, naive_change_email, naive_change_password,
                      password_matches, reauthenticate, touch)

START = 1_700_000_000.0
HOURS = 60 * 60


class FakeClock:
    """Manually advanced clock."""

    def __init__(self, start: float = START) -> None:
        self.current = start

    def now(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


def make_password() -> str:
    """Random password built at runtime."""
    return secrets.token_urlsafe(12)


class AccountFixture(unittest.TestCase):
    """Owner logs in on a shared computer; the clock then moves on."""

    def setUp(self):
        self.clock = FakeClock()
        self.owner_password = make_password()
        self.attacker_password = make_password()
        self.account = Account(1, "owner@example.test", hash_password(self.owner_password))
        self.session = log_in(self.account, self.owner_password, self.clock)

    def steal_cookie_later(self) -> None:
        """Attacker uses the left-behind session two hours after login."""
        self.clock.advance(2 * HOURS)
        touch(self.session, self.clock)


class ReproduceProblem(AccountFixture):
    def test_stolen_session_changes_password_and_email_without_current_password(self):
        self.steal_cookie_later()
        naive_change_password(self.session, self.account, self.attacker_password)
        naive_change_email(self.session, self.account, "attacker@evil.test")
        self.assertFalse(password_matches(self.owner_password, self.account.password_hash))
        self.assertEqual(self.account.email, "attacker@evil.test")


class FixStepUpReauthentication(AccountFixture):
    def test_stale_session_cannot_change_password(self):
        self.steal_cookie_later()
        with self.assertRaises(StepUpRequired):
            change_password(self.session, self.account, self.attacker_password, self.clock)
        self.assertTrue(password_matches(self.owner_password, self.account.password_hash))

    def test_stale_session_cannot_change_email(self):
        self.steal_cookie_later()
        with self.assertRaises(StepUpRequired):
            change_email(self.session, self.account, "attacker@evil.test", self.clock)
        self.assertEqual(self.account.email, "owner@example.test")

    def test_stale_session_cannot_disable_mfa(self):
        self.steal_cookie_later()
        with self.assertRaises(StepUpRequired):
            disable_mfa(self.session, self.account, self.clock)
        self.assertTrue(self.account.mfa_enabled)

    def test_wrong_current_password_is_rejected(self):
        self.steal_cookie_later()
        with self.assertRaises(StepUpRequired):
            change_password(self.session, self.account, self.attacker_password,
                            self.clock, current_password=make_password())

    def test_correct_current_password_allows_change(self):
        self.steal_cookie_later()
        new_password = make_password()
        change_password(self.session, self.account, new_password, self.clock,
                        current_password=self.owner_password)
        self.assertTrue(password_matches(new_password, self.account.password_hash))

    def test_fresh_login_allows_change_without_password(self):
        self.clock.advance(REAUTH_WINDOW_SECONDS - 1)
        change_email(self.session, self.account, "new@example.test", self.clock)
        self.assertEqual(self.account.email, "new@example.test")

    def test_window_boundary_is_inclusive_then_expires(self):
        self.clock.advance(REAUTH_WINDOW_SECONDS)
        change_email(self.session, self.account, "edge@example.test", self.clock)
        self.clock.advance(1)
        with self.assertRaises(StepUpRequired):
            change_email(self.session, self.account, "late@example.test", self.clock)

    def test_ordinary_activity_does_not_refresh_auth_time(self):
        for _minute in range(30):
            self.clock.advance(60)
            touch(self.session, self.clock)
        with self.assertRaises(StepUpRequired):
            disable_mfa(self.session, self.account, self.clock)

    def test_reauthentication_reopens_the_window(self):
        self.steal_cookie_later()
        reauthenticate(self.session, self.account, self.owner_password, self.clock)
        self.clock.advance(60)
        disable_mfa(self.session, self.account, self.clock)
        self.assertFalse(self.account.mfa_enabled)

    def test_auth_time_in_the_future_is_not_trusted(self):
        self.session.auth_time = self.clock.now() + HOURS
        with self.assertRaises(StepUpRequired):
            change_email(self.session, self.account, "x@evil.test", self.clock)

    def test_repeated_wrong_passwords_end_the_session(self):
        self.steal_cookie_later()
        for _attempt in range(MAX_REAUTH_FAILURES):
            with self.assertRaises(StepUpRequired):
                reauthenticate(self.session, self.account, make_password(), self.clock)
        self.assertTrue(self.session.revoked)
        with self.assertRaises(SessionRevoked):
            reauthenticate(self.session, self.account, self.owner_password, self.clock)

    def test_session_cannot_act_on_another_account(self):
        other = Account(2, "other@example.test", hash_password(make_password()))
        with self.assertRaises(PermissionError):
            change_email(self.session, other, "x@evil.test", self.clock)
        self.assertEqual(other.email, "other@example.test")

    def test_wrong_login_password_creates_no_session(self):
        self.assertIsNone(log_in(self.account, make_password(), self.clock))


if __name__ == "__main__":
    unittest.main()
