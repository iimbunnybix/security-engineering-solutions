"""Keep the session cookie away from subdomains that serve customer content.

The app at ``app.example.com`` set its session cookie with
``Domain=.example.com`` so one login would also work on ``api.example.com``.
Browsers then send that cookie to *every* subdomain, including
``pages.example.com``, which hosts customers' own HTML. A customer page's
server (or its request logs) receives every visiting user's session, and
without ``HttpOnly`` its JavaScript can read it too.

The fix is a host-only cookie: no ``Domain`` attribute, the ``__Host-``
name prefix (browsers then refuse a ``Domain`` attribute and require
``Secure`` and ``Path=/``), plus ``HttpOnly`` and ``SameSite``. A validator
checks Set-Cookie headers in tests so the attribute cannot creep back in.
The RFC 6265 domain-matching rule is implemented to show who gets the cookie.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

HOST_PREFIX = "__Host-"
SESSION_COOKIE_NAME = HOST_PREFIX + "session"
ALLOWED_SAMESITE = ("lax", "strict")


@dataclass(frozen=True)
class Cookie:
    name: str
    value: str
    attributes: dict[str, str] = field(default_factory=dict)  # lower-case keys

    @property
    def domain(self) -> str | None:
        """The Domain attribute without a leading dot (RFC 6265 5.2.3)."""
        raw = self.attributes.get("domain")
        if not raw:
            return None
        return raw.lstrip(".").lower()


def parse_set_cookie(header: str) -> Cookie:
    """Parse one Set-Cookie header value into name, value and attributes."""
    name_value, *attribute_parts = header.split(";")
    name, _, value = name_value.partition("=")
    attributes: dict[str, str] = {}
    for part in attribute_parts:
        key, _, attribute_value = part.strip().partition("=")
        # Flags such as Secure and HttpOnly have no value; store "" for them.
        attributes[key.strip().lower()] = attribute_value.strip()
    return Cookie(name.strip(), value.strip(), attributes)


def is_ip_address(host: str) -> bool:
    """True for IPv4/IPv6 literals, which never domain-match a suffix."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def domain_matches(request_host: str, cookie_domain: str) -> bool:
    """RFC 6265 section 5.1.3: is ``request_host`` within ``cookie_domain``?"""
    host = request_host.lower()
    domain = cookie_domain.lower()
    if host == domain:
        return True
    # A suffix match must start at a label boundary: "evil-example.com"
    # does not match "example.com", but "pages.example.com" does.
    return host.endswith("." + domain) and not is_ip_address(host)


def browser_sends_cookie(cookie: Cookie, set_by_host: str, request_host: str) -> bool:
    """Would a browser attach ``cookie`` (set by ``set_by_host``) to ``request_host``?"""
    if cookie.domain is None:
        # Host-only cookie: returned only to exactly the host that set it.
        return request_host.lower() == set_by_host.lower()
    return domain_matches(request_host, cookie.domain)


def browser_accepts_host_prefix(cookie: Cookie, from_secure_origin: bool) -> bool:
    """Cookie-prefix rules: browsers drop a __Host- cookie that breaks them."""
    if not cookie.name.startswith(HOST_PREFIX):
        return True
    has_secure = "secure" in cookie.attributes
    has_domain = "domain" in cookie.attributes
    path_is_root = cookie.attributes.get("path") == "/"
    return from_secure_origin and has_secure and not has_domain and path_is_root


# --- original and fixed headers -------------------------------------------
def naive_session_header(session_id: str) -> str:
    """The bug: shared with every subdomain, readable by JavaScript, no SameSite."""
    return f"session={session_id}; Domain=.example.com; Path=/"


def session_header(session_id: str) -> str:
    """Host-only, HTTPS-only, hidden from JavaScript, not sent cross-site."""
    return f"{SESSION_COOKIE_NAME}={session_id}; Path=/; Secure; HttpOnly; SameSite=Lax"


def session_cookie_problems(header: str) -> list[str]:
    """Every reason this Set-Cookie header is unsafe for a session cookie."""
    cookie = parse_set_cookie(header)
    problems = []
    if "domain" in cookie.attributes:
        problems.append("Domain attribute shares the cookie with all subdomains")
    if not cookie.name.startswith(HOST_PREFIX):
        problems.append(f"name should start with {HOST_PREFIX} so browsers enforce host-only")
    if "secure" not in cookie.attributes:
        problems.append("missing Secure: cookie would be sent over plain HTTP")
    if "httponly" not in cookie.attributes:
        problems.append("missing HttpOnly: page JavaScript can read the session")
    if cookie.attributes.get("samesite", "").lower() not in ALLOWED_SAMESITE:
        problems.append("SameSite should be Lax or Strict")
    if cookie.attributes.get("path") != "/":
        problems.append("Path should be /")
    return problems
