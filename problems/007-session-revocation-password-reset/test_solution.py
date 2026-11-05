import unittest

from solution import AuthService, FakeClock, _digest

MIN, HOUR = 60, 3600


def make(revoke=True):
    clock = FakeClock(1_000_000)
    svc = AuthService(clock, revoke_on_password_change=revoke)
    svc.register("asha", "correct horse battery")
    return svc, clock


class ReproduceSurvivingSessions(unittest.TestCase):
    def test_old_laptop_still_logged_in_after_reset(self):
        svc, _ = make(revoke=False)
        lost_laptop = svc.login("asha", "correct horse battery")
        svc.reset_password("asha", "a brand new passphrase")
        self.assertEqual(svc.authenticate(lost_laptop), "asha")   # still works


class Revocation(unittest.TestCase):
    def test_reset_signs_out_every_device(self):
        svc, _ = make()
        devices = [svc.login("asha", "correct horse battery") for _ in range(3)]
        svc.reset_password("asha", "a brand new passphrase")
        self.assertEqual([svc.authenticate(t) for t in devices], [None, None, None])
        self.assertIsNone(svc.login("asha", "correct horse battery"))
        self.assertIsNotNone(svc.login("asha", "a brand new passphrase"))

    def test_change_password_keeps_caller_signed_in_only(self):
        svc, _ = make()
        phone = svc.login("asha", "correct horse battery")
        laptop = svc.login("asha", "correct horse battery")
        new_laptop = svc.change_password(laptop, "correct horse battery", "a brand new passphrase")
        self.assertNotEqual(new_laptop, laptop)
        self.assertIsNone(svc.authenticate(phone))
        self.assertIsNone(svc.authenticate(laptop))
        self.assertEqual(svc.authenticate(new_laptop), "asha")
        self.assertEqual(svc.active_sessions("asha"), 1)

    def test_change_password_requires_old_password_and_policy(self):
        svc, _ = make()
        t = svc.login("asha", "correct horse battery")
        with self.assertRaises(PermissionError):
            svc.change_password(t, "wrong", "a brand new passphrase")
        with self.assertRaises(ValueError):
            svc.change_password(t, "correct horse battery", "short")
        self.assertEqual(svc.authenticate(t), "asha")      # failed attempts revoke nothing
        with self.assertRaises(PermissionError):
            svc.change_password("not-a-session", "x", "y" * 12)

    def test_revocation_is_per_user(self):
        svc, _ = make()
        svc.register("ravi", "another long password")
        a = svc.login("asha", "correct horse battery")
        r = svc.login("ravi", "another long password")
        svc.revoke_all("asha")
        self.assertIsNone(svc.authenticate(a))
        self.assertEqual(svc.authenticate(r), "ravi")

    def test_new_login_after_revoke_works(self):
        svc, _ = make()
        svc.revoke_all("asha")
        t = svc.login("asha", "correct horse battery")
        self.assertEqual(svc.authenticate(t), "asha")

    def test_registering_an_existing_username_is_refused(self):
        svc, _ = make()
        with self.assertRaises(ValueError):
            svc.register("asha", "someone else entirely")

    def test_revoked_session_stays_dead_after_reregister_attempt(self):
        svc, _ = make()
        laptop = svc.login("asha", "correct horse battery")
        svc.reset_password("asha", "a brand new passphrase")
        with self.assertRaises(ValueError):
            svc.register("asha", "someone else entirely")
        self.assertIsNone(svc.authenticate(laptop))


class Expiry(unittest.TestCase):
    def test_idle_timeout_and_sliding_activity(self):
        svc, clock = make()
        t = svc.login("asha", "correct horse battery")
        for _ in range(4):
            clock.advance(25 * MIN)
            self.assertEqual(svc.authenticate(t), "asha")   # activity keeps it alive
        clock.advance(31 * MIN)
        self.assertIsNone(svc.authenticate(t))

    def test_absolute_lifetime_even_if_active(self):
        svc, clock = make()
        t = svc.login("asha", "correct horse battery")
        for _ in range(12 * 4):
            clock.advance(15 * MIN)
            last = svc.authenticate(t)
        self.assertEqual(last, "asha")
        clock.advance(1)
        self.assertIsNone(svc.authenticate(t))


class Storage(unittest.TestCase):
    def test_only_token_hash_is_stored(self):
        svc, _ = make()
        t = svc.login("asha", "correct horse battery")
        self.assertNotIn(t, svc.sessions)
        self.assertIn(_digest(t), svc.sessions)
        self.assertGreaterEqual(len(t), 43)                 # 32 random bytes, base64url

    def test_dead_sessions_are_removed(self):
        svc, _ = make()
        t = svc.login("asha", "correct horse battery")
        svc.revoke_all("asha")
        svc.authenticate(t)
        self.assertEqual(len(svc.sessions), 0)

    def test_bad_inputs(self):
        svc, _ = make()
        self.assertIsNone(svc.authenticate(None))
        self.assertIsNone(svc.authenticate(""))
        self.assertIsNone(svc.login("nobody", "x"))
        t = svc.login("asha", "correct horse battery")
        svc.logout(t)
        self.assertIsNone(svc.authenticate(t))


if __name__ == "__main__":
    unittest.main()
