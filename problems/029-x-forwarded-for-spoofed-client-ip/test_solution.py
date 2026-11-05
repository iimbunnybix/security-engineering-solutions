import random
import unittest

from solution import (
    FAILURE_WINDOW_S,
    MAX_FAILURES_PER_IP,
    LoginThrottle,
    admin_allowed,
    naive_client_ip,
    parse_networks,
    trusted_client_ip,
)

LOAD_BALANCER = "10.0.0.5"          # our edge load balancer
INGRESS = "10.0.1.7"                # our ingress proxy behind it
TRUSTED_PROXIES = parse_networks(["10.0.0.0/16", "fd00::/8"])
OFFICE_VPN = parse_networks(["172.16.0.0/12"])
ATTACKER = "198.51.100.23"
OFFICE_LAPTOP = "172.16.4.20"
ATTEMPTS = 1000


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def via_load_balancer(client_sent_header=None, real_client=ATTACKER):
    """What the app sees: the LB appends the real client to whatever the client sent."""
    hops = [client_sent_header] if client_sent_header else []
    hops.append(real_client)
    return LOAD_BALANCER, {"X-Forwarded-For": ", ".join(hops)}


def random_ip(rng):
    return ".".join(str(rng.randrange(1, 255)) for _ in range(4))


def fixed_ip(peer, headers):
    return trusted_client_ip(peer, headers, TRUSTED_PROXIES)


def failures_allowed(throttle, rng):
    """How many wrong passwords an attacker spoofing a fresh IP per request gets in."""
    allowed = 0
    for _ in range(ATTEMPTS):
        peer, headers = via_load_balancer(random_ip(rng))
        if throttle.allowed(peer, headers):
            allowed += 1
            throttle.record_failure(peer, headers)
    return allowed


class ReproduceProblem(unittest.TestCase):
    def test_spoofed_header_gives_unlimited_password_guesses(self):
        throttle = LoginThrottle(FakeClock(), naive_client_ip)
        self.assertEqual(failures_allowed(throttle, random.Random(29)), ATTEMPTS)

    def test_spoofed_vpn_address_opens_the_admin_panel(self):
        peer, headers = via_load_balancer(OFFICE_LAPTOP)
        self.assertTrue(admin_allowed(naive_client_ip(peer, headers), OFFICE_VPN))


class FixClientIpResolution(unittest.TestCase):
    def test_left_most_spoofed_value_is_ignored(self):
        peer, headers = via_load_balancer("1.2.3.4")
        self.assertEqual(fixed_ip(peer, headers), ATTACKER)

    def test_chain_of_two_trusted_proxies_is_walked(self):
        headers = {"X-Forwarded-For": f"6.6.6.6, {ATTACKER}, {LOAD_BALANCER}"}
        self.assertEqual(fixed_ip(INGRESS, headers), ATTACKER)

    def test_direct_connection_ignores_the_header(self):
        headers = {"X-Forwarded-For": OFFICE_LAPTOP}
        self.assertEqual(fixed_ip(ATTACKER, headers), ATTACKER)

    def test_request_without_header_uses_the_peer(self):
        self.assertEqual(fixed_ip(ATTACKER, {}), ATTACKER)

    def test_garbage_entry_from_trusted_proxy_stops_the_walk(self):
        headers = {"X-Forwarded-For": f"{OFFICE_LAPTOP}, not-an-ip"}
        self.assertEqual(fixed_ip(LOAD_BALANCER, headers), LOAD_BALANCER)

    def test_client_claiming_to_be_a_proxy_is_not_trusted_further(self):
        # The attacker writes "vpn, our-proxy"; the LB then appends the real IP.
        peer, headers = via_load_balancer(f"{OFFICE_LAPTOP}, {INGRESS}")
        self.assertEqual(fixed_ip(peer, headers), ATTACKER)

    def test_ipv6_client_behind_ipv6_proxy(self):
        headers = {"X-Forwarded-For": "2001:db8::42"}
        self.assertEqual(fixed_ip("fd00::1", headers), "2001:db8::42")

    def test_invalid_peer_is_rejected(self):
        with self.assertRaises(ValueError):
            fixed_ip("unix-socket", {})


class FixThrottleAndAllowlist(unittest.TestCase):
    def test_spoofing_attacker_is_limited_to_the_per_ip_budget(self):
        throttle = LoginThrottle(FakeClock(), fixed_ip)
        self.assertEqual(failures_allowed(throttle, random.Random(29)), MAX_FAILURES_PER_IP)

    def test_budget_returns_after_the_window(self):
        clock = FakeClock()
        throttle = LoginThrottle(clock, fixed_ip)
        failures_allowed(throttle, random.Random(29))
        clock.advance(FAILURE_WINDOW_S + 1)
        self.assertTrue(throttle.allowed(*via_load_balancer("9.9.9.9")))

    def test_other_clients_are_not_affected(self):
        throttle = LoginThrottle(FakeClock(), fixed_ip)
        failures_allowed(throttle, random.Random(29))
        self.assertTrue(throttle.allowed(*via_load_balancer(real_client="203.0.113.50")))

    def test_spoofed_vpn_address_is_refused_by_admin_allowlist(self):
        peer, headers = via_load_balancer(OFFICE_LAPTOP)
        self.assertFalse(admin_allowed(fixed_ip(peer, headers), OFFICE_VPN))

    def test_real_office_laptop_is_allowed_into_admin(self):
        peer, headers = via_load_balancer(real_client=OFFICE_LAPTOP)
        self.assertTrue(admin_allowed(fixed_ip(peer, headers), OFFICE_VPN))

    def test_garbage_ip_is_never_on_the_allowlist(self):
        self.assertFalse(admin_allowed("not-an-ip", OFFICE_VPN))


if __name__ == "__main__":
    unittest.main()
