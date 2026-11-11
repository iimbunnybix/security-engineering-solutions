import unittest

from solution import (MAX_FAILURES_PER_WINDOW, WINDOW_SECONDS, FakeClock, client_key,
                      count_guesses_allowed, fixed_throttle, naive_throttle,
                      rotating_ipv6_addresses)

ATTACKER_PREFIX = "2001:db8:aa:bb::/64"
NEIGHBOUR_IP = "2001:db8:aa:cc::7"          # another customer's /64
GUESS_COUNT = 1_000
SECONDS_BETWEEN_GUESSES = 0.5               # 1,000 guesses in about 8 minutes


def attacker_addresses() -> list[str]:
    return rotating_ipv6_addresses(ATTACKER_PREFIX, GUESS_COUNT)


def exhaust(throttle, client_ip: str) -> None:
    """Use up every allowed failure for this client."""
    for _ in range(MAX_FAILURES_PER_WINDOW):
        throttle.record_failure(client_ip)


class ReproduceProblem(unittest.TestCase):
    def test_attacker_addresses_are_all_different(self):
        self.assertEqual(len(set(attacker_addresses())), GUESS_COUNT)

    def test_rotating_addresses_get_every_guess_through(self):
        clock = FakeClock()
        allowed = count_guesses_allowed(naive_throttle(clock), attacker_addresses(),
                                        clock, SECONDS_BETWEEN_GUESSES)
        self.assertEqual(allowed, GUESS_COUNT)

    def test_two_spellings_of_one_address_are_separate_buckets(self):
        clock = FakeClock()
        throttle = naive_throttle(clock)
        exhaust(throttle, "2001:db8::1")
        self.assertTrue(throttle.is_allowed("2001:DB8:0:0::1"))


class FixKeyBySubscriberNetwork(unittest.TestCase):
    def test_rotating_addresses_share_one_limit(self):
        clock = FakeClock()
        allowed = count_guesses_allowed(fixed_throttle(clock), attacker_addresses(),
                                        clock, SECONDS_BETWEEN_GUESSES)
        self.assertEqual(allowed, MAX_FAILURES_PER_WINDOW)

    def test_neighbouring_network_is_not_blocked_by_the_attacker(self):
        clock = FakeClock()
        throttle = fixed_throttle(clock)
        exhaust(throttle, attacker_addresses()[0])
        self.assertTrue(throttle.is_allowed(NEIGHBOUR_IP))

    def test_limit_resets_after_the_window(self):
        clock = FakeClock()
        throttle = fixed_throttle(clock)
        exhaust(throttle, attacker_addresses()[0])
        self.assertFalse(throttle.is_allowed(attacker_addresses()[1]))
        clock.advance(WINDOW_SECONDS)
        self.assertTrue(throttle.is_allowed(attacker_addresses()[1]))

    def test_different_spellings_of_one_address_share_a_key(self):
        self.assertEqual(client_key("2001:db8::1"), client_key("2001:DB8:0:0::1"))


class FixIpv4Handling(unittest.TestCase):
    def test_ipv4_is_keyed_by_full_address(self):
        self.assertEqual(client_key("203.0.113.5"), "203.0.113.5")
        self.assertNotEqual(client_key("203.0.113.5"), client_key("203.0.113.6"))

    def test_ipv4_mapped_address_is_the_same_client_as_plain_ipv4(self):
        self.assertEqual(client_key("::ffff:203.0.113.5"), "203.0.113.5")

    def test_mapped_ipv4_clients_do_not_share_one_ipv6_bucket(self):
        clock = FakeClock()
        throttle = fixed_throttle(clock)
        exhaust(throttle, "::ffff:203.0.113.5")
        self.assertTrue(throttle.is_allowed("::ffff:198.51.100.9"))


class FixInvalidInput(unittest.TestCase):
    def test_non_ip_value_is_rejected_not_given_a_fresh_bucket(self):
        with self.assertRaises(ValueError):
            client_key("not-an-ip")

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(client_key(" 203.0.113.5 "), "203.0.113.5")


if __name__ == "__main__":
    unittest.main()
