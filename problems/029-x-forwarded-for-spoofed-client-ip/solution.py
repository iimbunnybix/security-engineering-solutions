"""Find the real client IP behind proxies without trusting spoofable headers.

The login rate limiter and the admin-panel IP allowlist both keyed on the
client IP, which the app took from the *left-most* ``X-Forwarded-For`` value.
That value is whatever the client sent: proxies append to the header, they do
not replace it. An attacker set a random IP per request to get unlimited
password guesses, and set an office VPN address to pass the admin allowlist.

The fix walks the chain from the right, starting at the TCP peer. Each hop
is accepted only while the address that reported it is one of our own
proxies (configured CIDRs). The first address not in that set is the client.
"""
from __future__ import annotations

import ipaddress
from collections import deque
from typing import Callable, Iterable

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Clock = Callable[[], float]

MAX_FAILURES_PER_IP = 5
FAILURE_WINDOW_S = 15 * 60
FORWARDED_HEADER = "X-Forwarded-For"


def parse_networks(cidrs: Iterable[str]) -> list[IPNetwork]:
    """Turn config strings like "10.0.0.0/24" into network objects."""
    return [ipaddress.ip_network(cidr) for cidr in cidrs]


def parse_ip(text: str) -> IPAddress | None:
    """Parse one address from a header, or None if it is not an IP at all."""
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        return None


def in_any(address: IPAddress, networks: list[IPNetwork]) -> bool:
    """True if ``address`` is inside one of ``networks``."""
    for network in networks:
        if address.version == network.version and address in network:
            return True
    return False


def forwarded_hops(headers: dict[str, str]) -> list[str]:
    """The comma-separated X-Forwarded-For entries, left (oldest) to right."""
    raw = headers.get(FORWARDED_HEADER, "")
    if not raw.strip():
        return []
    return [hop.strip() for hop in raw.split(",")]


# --- original version ---------------------------------------------------
def naive_client_ip(peer: str, headers: dict[str, str]) -> str:
    """The bug: believe the left-most X-Forwarded-For entry, which the client controls."""
    hops = forwarded_hops(headers)
    if hops:
        return hops[0]
    return peer


# --- fixed version ------------------------------------------------------
def trusted_client_ip(peer: str, headers: dict[str, str],
                      trusted_proxies: list[IPNetwork]) -> str:
    """The client IP as vouched for by our own proxies.

    Start from the TCP peer (cannot be spoofed). While the current address is
    one of our proxies, the entry it appended (the right-most one not yet
    used) tells us who connected to it, so step to that entry. Stop at the
    first address that is not our proxy: everything to its left was written
    by that untrusted party and could be made up.
    """
    current = parse_ip(peer)
    if current is None:
        raise ValueError(f"peer address is not an IP: {peer!r}")
    hops = forwarded_hops(headers)
    while in_any(current, trusted_proxies) and hops:
        previous_hop = parse_ip(hops.pop())
        if previous_hop is None:
            # A proxy we trust appended garbage; do not guess past it.
            break
        current = previous_hop
    return str(current)


class LoginThrottle:
    """At most MAX_FAILURES_PER_IP failed logins per IP per rolling window."""

    def __init__(self, clock: Clock, client_ip: Callable[[str, dict[str, str]], str]) -> None:
        self.clock = clock
        self.client_ip = client_ip
        self.failures: dict[str, deque] = {}

    def allowed(self, peer: str, headers: dict[str, str]) -> bool:
        """May this request try a password right now?"""
        return len(self._recent(self.client_ip(peer, headers))) < MAX_FAILURES_PER_IP

    def record_failure(self, peer: str, headers: dict[str, str]) -> None:
        """Count a wrong password against the request's client IP."""
        self._recent(self.client_ip(peer, headers)).append(self.clock())

    def _recent(self, ip: str) -> deque:
        """Failure times for ``ip`` inside the window, older ones dropped."""
        times = self.failures.setdefault(ip, deque())
        window_start = self.clock() - FAILURE_WINDOW_S
        while times and times[0] <= window_start:
            times.popleft()
        return times


def admin_allowed(client_ip: str, allowlist: list[IPNetwork]) -> bool:
    """The admin panel is only reachable from the office VPN ranges."""
    address = parse_ip(client_ip)
    return address is not None and in_any(address, allowlist)
