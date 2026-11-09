import unittest

from solution import (DAY, FAMILY_MAX_LIFETIME_SECONDS, MINUTE, REFRESH_TOKEN_TTL_SECONDS,
                      InvalidRefreshToken, NaiveRefreshStore, RefreshTokenReuse,
                      RotatingRefreshStore, token_digest)

START = 1_700_000_000.0


class FakeClock:
    """Manually advanced clock."""

    def __init__(self) -> None:
        self.current = START

    def now(self) -> float:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += seconds


class CountingTokens:
    """Predictable fake tokens built at runtime: fake-token-1, fake-token-2, ..."""

    def __init__(self) -> None:
        self.count = 0

    def __call__(self) -> str:
        self.count += 1
        return f"fake-token-{self.count}"


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.store = NaiveRefreshStore(self.clock.now, CountingTokens())
        self.stolen = self.store.login("asha").refresh_token

    def test_stolen_token_keeps_working_while_the_owner_uses_it_too(self):
        for _day in range(29):
            self.clock.advance(DAY)
            self.store.refresh(self.stolen)              # owner's app
            self.assertIsNotNone(self.store.refresh(self.stolen))  # thief

    def test_owner_refreshing_does_not_change_the_token(self):
        pair = self.store.refresh(self.stolen)
        self.assertEqual(pair.refresh_token, self.stolen)

    def test_token_only_stops_working_after_thirty_days(self):
        self.clock.advance(REFRESH_TOKEN_TTL_SECONDS)
        with self.assertRaises(InvalidRefreshToken):
            self.store.refresh(self.stolen)


class FixRotationWithReuseDetection(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.store = RotatingRefreshStore(self.clock.now, CountingTokens())
        self.first = self.store.login("asha")

    def refresh_twice_from_the_same_token(self) -> tuple:
        """First use succeeds, the second presentation is the reuse."""
        winner = self.store.refresh(self.first.refresh_token)
        with self.assertRaises(RefreshTokenReuse):
            self.store.refresh(self.first.refresh_token)
        return winner

    def test_refresh_returns_a_new_refresh_token(self):
        second = self.store.refresh(self.first.refresh_token)
        self.assertNotEqual(second.refresh_token, self.first.refresh_token)
        self.assertEqual(self.store.authenticate(second.access_token), "asha")

    def test_used_refresh_token_is_rejected_as_reuse(self):
        self.refresh_twice_from_the_same_token()

    def test_thief_refreshing_first_loses_access_when_owner_comes_back(self):
        thief = self.refresh_twice_from_the_same_token()
        self.assertIsNone(self.store.authenticate(thief.access_token))
        with self.assertRaises(InvalidRefreshToken):
            self.store.refresh(thief.refresh_token)

    def test_owner_refreshing_first_locks_out_a_later_thief(self):
        owner = self.refresh_twice_from_the_same_token()
        # Both lose the session: the server cannot know which copy is the owner's.
        self.assertIsNone(self.store.authenticate(owner.access_token))
        with self.assertRaises(InvalidRefreshToken):
            self.store.refresh(owner.refresh_token)

    def test_long_chain_of_rotations_keeps_working(self):
        pair = self.first
        for _day in range(29):
            self.clock.advance(DAY)
            pair = self.store.refresh(pair.refresh_token)
        self.assertEqual(self.store.authenticate(pair.access_token), "asha")

    def test_reusing_any_old_token_in_the_chain_revokes_the_family(self):
        second = self.store.refresh(self.first.refresh_token)
        third = self.store.refresh(second.refresh_token)
        with self.assertRaises(RefreshTokenReuse):
            self.store.refresh(second.refresh_token)
        with self.assertRaises(InvalidRefreshToken):
            self.store.refresh(third.refresh_token)

    def test_other_devices_are_not_affected_by_a_revoked_family(self):
        laptop = self.store.login("asha")
        self.refresh_twice_from_the_same_token()
        self.assertEqual(self.store.authenticate(laptop.access_token), "asha")
        self.assertIsNotNone(self.store.refresh(laptop.refresh_token))

    def test_idle_refresh_token_expires_after_thirty_days(self):
        self.clock.advance(REFRESH_TOKEN_TTL_SECONDS)
        with self.assertRaises(InvalidRefreshToken):
            self.store.refresh(self.first.refresh_token)

    def test_refresh_token_works_one_second_before_idle_expiry(self):
        self.clock.advance(REFRESH_TOKEN_TTL_SECONDS - 1)
        self.assertIsNotNone(self.store.refresh(self.first.refresh_token))

    def test_family_cannot_be_extended_past_its_absolute_lifetime(self):
        pair = self.first
        while self.clock.now() + 20 * DAY < START + FAMILY_MAX_LIFETIME_SECONDS:
            self.clock.advance(20 * DAY)
            pair = self.store.refresh(pair.refresh_token)
        self.clock.current = START + FAMILY_MAX_LIFETIME_SECONDS
        with self.assertRaises(InvalidRefreshToken):
            self.store.refresh(pair.refresh_token)

    def test_access_token_expires_after_fifteen_minutes(self):
        self.clock.advance(15 * MINUTE)
        self.assertIsNone(self.store.authenticate(self.first.access_token))

    def test_unknown_tokens_are_rejected(self):
        with self.assertRaises(InvalidRefreshToken):
            self.store.refresh("not-a-token")
        self.assertIsNone(self.store.authenticate("not-a-token"))

    def test_only_token_digests_are_stored(self):
        stored = self.store.stored_token_values()
        self.assertIn(token_digest(self.first.refresh_token), stored)
        self.assertNotIn(self.first.refresh_token, stored)
        self.assertNotIn(self.first.access_token, stored)


if __name__ == "__main__":
    unittest.main()
