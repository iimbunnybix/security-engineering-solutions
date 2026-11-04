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


if __name__ == "__main__":
    unittest.main()
