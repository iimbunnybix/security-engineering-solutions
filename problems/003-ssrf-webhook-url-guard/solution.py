"""SSRF guard for user-supplied webhook URLs.

Customers register a webhook URL and the server POSTs events to it. Without
validation an attacker registers ``http://169.254.169.254/latest/meta-data/``
(cloud instance metadata) or ``http://localhost:6379/`` and uses our server
as a proxy into the internal network.

Defences implemented here:
* scheme/port allow-list, no credentials in URL
* resolve the hostname ONCE, reject if ANY address is non-public
  (private, loopback, link-local, multicast, reserved, CGNAT, IPv4-mapped IPv6 ...)
* return the vetted IP so the caller connects to that exact IP (defeats DNS
  rebinding between check and use) while sending the original Host header
* redirects are not followed automatically; each hop is re-validated
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urljoin, urlsplit

Resolver = Callable[[str, int], Iterable[str]]


class BlockedURL(ValueError):
    pass


def system_resolver(host: str, port: int) -> list[str]:
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})


# Ranges Python's is_global may not cover on all versions, listed explicitly.
EXTRA_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15",
    "fc00::/7", "fe80::/10", "64:ff9b::/96",
    # Deprecated IPv6 site-local (RFC 3879): still used for internal hosts on
    # some networks, and Python 3.13 reports it as is_global.
    "fec0::/10",
)]


def is_public_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str.split("%", 1)[0])     # strip IPv6 zone id
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped or ip.sixtofour
        if mapped is not None:
            return is_public_ip(str(mapped))
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified or not ip.is_global):
        return False
    return not any(ip in net for net in EXTRA_BLOCKED if net.version == ip.version)


@dataclass(frozen=True)
class VettedTarget:
    url: str
    scheme: str
    host: str          # for the Host header / TLS SNI
    port: int
    ip: str            # connect to this exact address
    path: str


class WebhookURLValidator:
    def __init__(self, resolver: Resolver = system_resolver,
                 allowed_schemes: tuple[str, ...] = ("https",),
                 allowed_ports: tuple[int, ...] = (443,), max_redirects: int = 3):
        self.resolver = resolver
        self.allowed_schemes = allowed_schemes
        self.allowed_ports = allowed_ports
        self.max_redirects = max_redirects

    def validate(self, url: str) -> VettedTarget:
        if len(url) > 2048 or any(c in url for c in "\r\n\t\\ "):
            raise BlockedURL("malformed URL")
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        if scheme not in self.allowed_schemes:
            raise BlockedURL(f"scheme {scheme!r} not allowed")
        if parts.username or parts.password or "@" in parts.netloc:
            raise BlockedURL("credentials in URL not allowed")
        host = parts.hostname
        if not host:
            raise BlockedURL("missing host")
        try:
            port = parts.port or (443 if scheme == "https" else 80)
        except ValueError as e:
            raise BlockedURL("invalid port") from e
        if port not in self.allowed_ports:
            raise BlockedURL(f"port {port} not allowed")
        host = host.rstrip(".").lower()
        if host == "localhost" or host.endswith((".localhost", ".internal", ".local")):
            raise BlockedURL("internal hostname")
        try:
            addrs = list(self.resolver(host, port))
        except OSError as e:
            raise BlockedURL("DNS resolution failed") from e
        if not addrs:
            raise BlockedURL("host has no addresses")
        bad = [a for a in addrs if not is_public_ip(a)]
        if bad:                         # one private record is enough to refuse
            raise BlockedURL(f"resolves to non-public address {bad[0]}")
        return VettedTarget(url, scheme, host, port, addrs[0],
                            (parts.path or "/") + (f"?{parts.query}" if parts.query else ""))

    def follow(self, url: str, fetch: Callable[[VettedTarget], tuple[int, str | None]]
               ) -> tuple[int, VettedTarget]:
        """Deliver via ``fetch`` (which must connect to ``target.ip``), re-validating
        every redirect hop. ``fetch`` returns (status, location_header)."""
        target = self.validate(url)
        for _ in range(self.max_redirects + 1):
            status, location = fetch(target)
            if status not in (301, 302, 303, 307, 308) or not location:
                return status, target
            target = self.validate(urljoin(target.url, location))
        raise BlockedURL("too many redirects")
