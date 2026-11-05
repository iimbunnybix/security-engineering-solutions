import unittest

from solution import DEFAULT_TARGET, naive_redirect_target, safe_redirect_target

ALLOWED = ["app.example.com", "docs.example.com"]

ATTACKS = [
    "//evil.example/login",                 # scheme-relative
    "/\\evil.example",                      # backslash -> slash in browsers
    "\\\\evil.example",
    "/\t/evil.example",                     # tab stripped by browsers
    "/\n/evil.example",
    "  //evil.example",                     # leading whitespace stripped
    "https://evil.example/",
    "http://app.example.com/",              # downgrade to http
    "https:evil.example",                   # browsers read this as https://evil.example
    "https:/evil.example",
    "javascript:alert(document.cookie)",
    "JaVaScRiPt:alert(1)",
    " javascript:alert(1)",
    "data:text/html;base64,PHNjcmlwdD4=",
    "https://app.example.com@evil.example/",       # user-info trick
    "https://app.example.com:pw@evil.example/",
    "https://app.example.com.evil.example/",       # suffix trick
    "https://evil.example/?https://app.example.com",
    "https://app.example.com:8443/",               # unexpected port
    "https://app.example.com:99999/",              # invalid port
    "evil.example",                                 # no leading slash
    "/\x00/evil.example",
    "x" * 3000,
]


class ReproduceOpenRedirect(unittest.TestCase):
    def test_naive_check_lets_off_site_targets_through(self):
        leaked = [u for u in ("//evil.example/login", "/\\evil.example", "/\t/evil.example")
                  if naive_redirect_target(u) == u]
        self.assertEqual(len(leaked), 3)


class SafeRedirectFix(unittest.TestCase):
    def test_attacks_fall_back_to_default(self):
        for url in ATTACKS:
            with self.subTest(url=url[:60]):
                self.assertEqual(safe_redirect_target(url, ALLOWED), DEFAULT_TARGET)

    def test_local_paths_are_kept(self):
        for url in ["/", "/dashboard", "/invoices/42?tab=paid#row-3",
                    "/search?q=a:b", "/%2F%2Fevil.example", "/a//b"]:
            with self.subTest(url=url):
                self.assertEqual(safe_redirect_target(url, ALLOWED), url)

    def test_allowed_absolute_hosts(self):
        self.assertEqual(safe_redirect_target("https://docs.example.com/guide?x=1", ALLOWED),
                         "https://docs.example.com/guide?x=1")
        self.assertEqual(safe_redirect_target("https://APP.example.com", ALLOWED),
                         "https://app.example.com/")
        self.assertEqual(safe_redirect_target("https://app.example.com:443/x", ALLOWED),
                         "https://app.example.com/x")
        self.assertEqual(safe_redirect_target("https://app.example.com./x", ALLOWED),
                         "https://app.example.com/x")

    def test_absolute_urls_rejected_without_allow_list(self):
        self.assertEqual(safe_redirect_target("https://app.example.com/x"), DEFAULT_TARGET)

    def test_missing_or_empty(self):
        self.assertEqual(safe_redirect_target(None), DEFAULT_TARGET)
        self.assertEqual(safe_redirect_target(""), DEFAULT_TARGET)
        self.assertEqual(safe_redirect_target("   "), DEFAULT_TARGET)

    def test_custom_default(self):
        self.assertEqual(safe_redirect_target("//evil.example", default="/home"), "/home")

    def test_trailing_whitespace_is_stripped_like_browsers(self):
        self.assertEqual(safe_redirect_target("/dashboard  "), "/dashboard")


class FixNonAsciiLocationHeader(unittest.TestCase):
    def test_c1_control_character_falls_back_to_default(self):
        self.assertEqual(safe_redirect_target("/\x85/evil.example", ALLOWED), DEFAULT_TARGET)

    def test_line_separator_is_percent_encoded(self):
        self.assertEqual(safe_redirect_target("/reports/q3\u2028summary", ALLOWED),
                         "/reports/q3%E2%80%A8summary")

    def test_unicode_query_and_fragment_are_percent_encoded(self):
        self.assertEqual(safe_redirect_target("/search?q=caf\u00e9#r\u00e9sum\u00e9"),
                         "/search?q=caf%C3%A9#r%C3%A9sum%C3%A9")

    def test_result_is_always_ascii_and_latin1_encodable(self):
        for url in ["/r\u2028x", "https://app.example.com/\u00fcber", "/ok"]:
            with self.subTest(url=url):
                location = safe_redirect_target(url, ALLOWED)
                self.assertTrue(location.isascii())
                location.encode("latin-1")


class FixBackslashInQueryAndFragment(unittest.TestCase):
    def test_backslash_in_query_is_preserved(self):
        self.assertEqual(safe_redirect_target("/files?path=C:\\Users\\me", ALLOWED),
                         "/files?path=C:\\Users\\me")

    def test_backslash_in_fragment_is_preserved(self):
        self.assertEqual(safe_redirect_target("/search?q=a\\b#x\\y"),
                         "/search?q=a\\b#x\\y")

    def test_backslash_before_query_is_still_rejected(self):
        self.assertEqual(safe_redirect_target("/\\evil.example?next=1"), DEFAULT_TARGET)

    def test_backslash_after_hash_does_not_hide_host(self):
        self.assertEqual(safe_redirect_target("/#\\evil.example"), "/#\\evil.example")


if __name__ == "__main__":
    unittest.main()
