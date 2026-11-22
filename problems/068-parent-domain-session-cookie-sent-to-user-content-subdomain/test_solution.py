import secrets
import unittest

from solution import (
    SESSION_COOKIE_NAME,
    browser_accepts_host_prefix,
    browser_sends_cookie,
    domain_matches,
    naive_session_header,
    parse_set_cookie,
    session_cookie_problems,
    session_header,
)

APP_HOST = "app.example.com"
USER_CONTENT_HOST = "pages.example.com"


def fake_session_id():
    # Built at runtime so no secret-looking literal is committed.
    return secrets.token_urlsafe(16)


def hosts_receiving(header, hosts):
    cookie = parse_set_cookie(header)
    return [host for host in hosts if browser_sends_cookie(cookie, APP_HOST, host)]


class ReproduceProblem(unittest.TestCase):
    def test_parent_domain_cookie_is_sent_to_the_user_content_host(self):
        cookie = parse_set_cookie(naive_session_header(fake_session_id()))
        self.assertTrue(browser_sends_cookie(cookie, APP_HOST, USER_CONTENT_HOST))

    def test_parent_domain_cookie_reaches_every_subdomain(self):
        hosts = [APP_HOST, USER_CONTENT_HOST, "api.example.com", "example.com", "old.staging.example.com"]
        self.assertEqual(hosts_receiving(naive_session_header(fake_session_id()), hosts), hosts)

    def test_naive_cookie_is_readable_by_javascript(self):
        cookie = parse_set_cookie(naive_session_header(fake_session_id()))
        self.assertNotIn("httponly", cookie.attributes)


class DomainMatching(unittest.TestCase):
    def test_identical_host_matches(self):
        self.assertTrue(domain_matches("Example.COM", "example.com"))

    def test_subdomain_matches(self):
        self.assertTrue(domain_matches("pages.example.com", "example.com"))

    def test_suffix_without_a_dot_boundary_does_not_match(self):
        self.assertFalse(domain_matches("evil-example.com", "example.com"))

    def test_parent_does_not_match_a_subdomain_cookie(self):
        self.assertFalse(domain_matches("example.com", "app.example.com"))

    def test_ip_address_never_suffix_matches(self):
        self.assertFalse(domain_matches("10.0.0.1", "0.0.1"))

    def test_leading_dot_in_domain_attribute_is_ignored(self):
        cookie = parse_set_cookie("a=b; Domain=.Example.com")
        self.assertEqual(cookie.domain, "example.com")


class FixHostOnlySessionCookie(unittest.TestCase):
    def setUp(self):
        self.header = session_header(fake_session_id())
        self.cookie = parse_set_cookie(self.header)

    def test_cookie_is_sent_only_to_the_app_host(self):
        hosts = [APP_HOST, USER_CONTENT_HOST, "api.example.com", "example.com"]
        self.assertEqual(hosts_receiving(self.header, hosts), [APP_HOST])

    def test_fixed_header_passes_the_validator(self):
        self.assertEqual(session_cookie_problems(self.header), [])

    def test_fixed_cookie_uses_the_host_prefix(self):
        self.assertEqual(self.cookie.name, SESSION_COOKIE_NAME)

    def test_browser_accepts_the_fixed_cookie_over_https(self):
        self.assertTrue(browser_accepts_host_prefix(self.cookie, from_secure_origin=True))

    def test_browser_rejects_host_prefix_cookie_from_plain_http(self):
        self.assertFalse(browser_accepts_host_prefix(self.cookie, from_secure_origin=False))

    def test_browser_rejects_host_prefix_cookie_with_a_domain(self):
        bad = parse_set_cookie(self.header + "; Domain=example.com")
        self.assertFalse(browser_accepts_host_prefix(bad, from_secure_origin=True))

    def test_browser_rejects_host_prefix_cookie_with_a_narrow_path(self):
        bad = parse_set_cookie(f"{SESSION_COOKIE_NAME}=x; Path=/app; Secure")
        self.assertFalse(browser_accepts_host_prefix(bad, from_secure_origin=True))


class FixValidatorCatchesRegressions(unittest.TestCase):
    def test_naive_header_reports_every_problem(self):
        problems = session_cookie_problems(naive_session_header(fake_session_id()))
        self.assertEqual(len(problems), 5)
        self.assertTrue(problems[0].startswith("Domain attribute"))

    def test_samesite_none_is_reported(self):
        header = session_header(fake_session_id()).replace("SameSite=Lax", "SameSite=None")
        self.assertEqual(session_cookie_problems(header), ["SameSite should be Lax or Strict"])

    def test_attribute_names_are_case_insensitive(self):
        header = f"{SESSION_COOKIE_NAME}=x; path=/; SECURE; httponly; samesite=strict"
        self.assertEqual(session_cookie_problems(header), [])


if __name__ == "__main__":
    unittest.main()
