"""Login throttling that an IPv6 attacker cannot dodge by changing address.

The login endpoint limited failed attempts per client IP, using the address
string as the key. Every IPv6 customer line gets at least a /64 network, which
is 2**64 addresses, so an attacker simply used a new address for every guess
and was never throttled. This module keys IPv6 clients by their /64 network
(the smallest block one subscriber normally gets), keys IPv4 clients by their
full address, and turns IPv4-mapped IPv6 addresses ("::ffff:203.0.113.5", as a
dual-stack socket reports IPv4 clients) back into plain IPv4 first.
"""
from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

MAX_FAILURES_PER_WINDOW = 10
WINDOW_SECONDS = 15 * 60
# One subscriber (home line, phone, cloud VM) is normally given at least a /64.
IPV6_SUBSCRIBER_PREFIX_LENGTH = 64


class FakeClock:
    """A clock the tests move forward by hand, so windows are deterministic."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def time(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def naive_client_key(client_ip: str) -> str:
    """Original key: the raw address string, so each IPv6 address is a new client."""
    return client_ip


def client_key(client_ip: str) -> str:
    """Throttle key for one subscriber: full IPv4 address or IPv6 /64 network.

    Raises ValueError for anything that is not an IP address, so a garbage
    value can never become its own fresh, unthrottled bucket.
    """
    address = ipaddress.ip_address(client_ip.strip())
    if isinstance(address, ipaddress.IPv6Address):
        # Must come before the /64 step: every mapped IPv4 address lives in
        # ::/64, so without this all IPv4 users would share one bucket.
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        network = ipaddress.IPv6Network((address, IPV6_SUBSCRIBER_PREFIX_LENGTH), strict=False)
        return str(network)
    return str(address)


@dataclass
class LoginThrottle:
    """Allow at most MAX_FAILURES_PER_WINDOW failed logins per key per window."""
    clock: FakeClock
    key_function: Callable[[str], str] = client_key
    failures: dict[str, deque] = field(default_factory=dict)

    def _recent_failures(self, key: str) -> deque:
        """Failure times for this key, with ones older than the window dropped."""
        times = self.failures.setdefault(key, deque())
        oldest_allowed = self.clock.time() - WINDOW_SECONDS
        while times and times[0] <= oldest_allowed:
            times.popleft()
        return times

    def is_allowed(self, client_ip: str) -> bool:
        """True if this client may try another password right now."""
        key = self.key_function(client_ip)
        return len(self._recent_failures(key)) < MAX_FAILURES_PER_WINDOW

    def record_failure(self, client_ip: str) -> None:
        """Count one wrong password against this client's key."""
        key = self.key_function(client_ip)
        self._recent_failures(key).append(self.clock.time())


def naive_throttle(clock: FakeClock) -> LoginThrottle:
    """The original throttle: same counting, keyed by the raw address string."""
    return LoginThrottle(clock, key_function=naive_client_key)


def fixed_throttle(clock: FakeClock) -> LoginThrottle:
    """The fixed throttle: keyed by subscriber (IPv4 address or IPv6 /64)."""
    return LoginThrottle(clock, key_function=client_key)


def rotating_ipv6_addresses(prefix: str, count: int) -> list[str]:
    """Generate `count` different addresses inside one /64, as an attacker would."""
    network = ipaddress.IPv6Network(prefix)
    addresses = []
    for host_number in range(1, count + 1):
        # Spread the host part out like random SLAAC/privacy addresses do.
        offset = host_number * 0x9E3779B97F4A7C15 % network.num_addresses
        addresses.append(str(network[offset]))
    return addresses


def count_guesses_allowed(throttle: LoginThrottle, client_ips: list[str],
                          clock: FakeClock, seconds_between_guesses: float) -> int:
    """Simulate one wrong guess per address; return how many got past the throttle."""
    allowed = 0
    for client_ip in client_ips:
        if throttle.is_allowed(client_ip):
            allowed += 1
            throttle.record_failure(client_ip)
        clock.advance(seconds_between_guesses)
    return allowed
