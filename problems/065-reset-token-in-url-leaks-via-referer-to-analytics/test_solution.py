import unittest
from urllib.parse import urlsplit

from solution import (
    SESSION_TTL_SECONDS,
    SITE,
    TOKEN_TTL_SECONDS,
    FakeClock,
    ResetService,
    cookie_from,
    naive_reset_page,
    outgoing_requests,
    parse_policy_header,
    referer_for,
)

EMAIL = "asha@mail.example"
OUR_HOST = urlsplit(SITE).hostname


def third_party_referers(page_url, response):
    """Referer values that reached hosts other than ours."""
    return [referer for url, referer in outgoing_requests(page_url, response)
            if urlsplit(url).hostname != OUR_HOST]


def run_fixed_flow(service, token):
    """Follow the emailed link like a browser: exchange, redirect, load the form."""
    start_url = service.reset_link(token)
    redirect = service.start(start_url)
    form_url = redirect.headers["Location"]
    form = service.form(cookie_from(redirect))
    return start_url, redirect, form_url, form


class ReproduceProblem(unittest.TestCase):
    def test_naive_page_sends_the_token_to_every_third_party(self):
        page_url = f"{SITE}/reset?token=live-token-value"
        referers = third_party_referers(page_url, naive_reset_page(page_url))
        self.assertEqual(len(referers), 3)
        for referer in referers:
            self.assertIn("token=live-token-value", referer)

    def test_legacy_downgrade_policy_also_leaks_to_https_vendors(self):
        page_url = f"{SITE}/reset?token=abc"
        referer = referer_for(page_url, "https://cdn.analytics.example/tag.js",
                              "no-referrer-when-downgrade")
        self.assertEqual(referer, page_url)


class FixedFlowNeverLeaksTheToken(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.service = ResetService(self.clock)
        self.token = self.service.issue_token(EMAIL)

    def test_exchange_endpoint_redirects_with_303_to_a_token_free_url(self):
        _, redirect, form_url, _ = run_fixed_flow(self.service, self.token)
        self.assertEqual(redirect.status, 303)
        self.assertEqual(form_url, f"{SITE}/reset")
        self.assertNotIn(self.token, form_url)

    def test_redirect_response_loads_nothing_and_sends_no_referrer(self):
        _, redirect, _, _ = run_fixed_flow(self.service, self.token)
        self.assertEqual(redirect.subresources, ())
        self.assertEqual(redirect.headers["Referrer-Policy"], "no-referrer")

    def test_session_cookie_is_httponly_secure_strict_and_short_lived(self):
        _, redirect, _, _ = run_fixed_flow(self.service, self.token)
        cookie = redirect.headers["Set-Cookie"]
        for attribute in ("HttpOnly", "Secure", "SameSite=Strict", f"Max-Age={SESSION_TTL_SECONDS}"):
            self.assertIn(attribute, cookie)

    def test_form_page_loads_no_third_party_resources(self):
        _, _, form_url, form = run_fixed_flow(self.service, self.token)
        self.assertEqual(form.status, 200)
        self.assertEqual(third_party_referers(form_url, form), [])

    def test_form_page_sends_no_referer_even_to_its_own_files(self):
        _, _, form_url, form = run_fixed_flow(self.service, self.token)
        self.assertTrue(all(referer is None for _, referer in outgoing_requests(form_url, form)))

    def test_token_cannot_be_exchanged_twice(self):
        run_fixed_flow(self.service, self.token)
        self.assertEqual(self.service.start(self.service.reset_link(self.token)).status, 400)

    def test_expired_token_is_rejected(self):
        self.clock.now += TOKEN_TTL_SECONDS
        self.assertEqual(self.service.start(self.service.reset_link(self.token)).status, 400)

    def test_session_expires_after_its_ttl(self):
        _, redirect, _, _ = run_fixed_flow(self.service, self.token)
        self.clock.now += SESSION_TTL_SECONDS
        self.assertEqual(self.service.form(cookie_from(redirect)).status, 403)

    def test_session_sets_the_password_only_once(self):
        _, redirect, _, _ = run_fixed_flow(self.service, self.token)
        cookies = cookie_from(redirect)
        self.assertTrue(self.service.submit(cookies, "new long passphrase 1"))
        self.assertFalse(self.service.submit(cookies, "attacker passphrase 2"))
        self.assertIn(EMAIL, self.service.passwords)

    def test_form_without_cookie_is_refused(self):
        self.assertEqual(self.service.form({}).status, 403)

    def test_only_hashes_of_tokens_are_stored(self):
        self.assertNotIn(self.token, self.service.tokens)


class FixReferrerPolicyModel(unittest.TestCase):
    PAGE = "https://user:pw@accounts.shop.example/reset?token=t1#step2"
    SAME = "https://accounts.shop.example/static/reset.js"
    CROSS = "https://cdn.analytics.example/tag.js"
    INSECURE = "http://cdn.analytics.example/tag.js"
    FULL = "https://accounts.shop.example/reset?token=t1"
    ORIGIN = "https://accounts.shop.example/"

    def test_fragment_and_userinfo_are_always_stripped(self):
        self.assertEqual(referer_for(self.PAGE, self.CROSS, "unsafe-url"), self.FULL)

    def test_unsafe_url_sends_full_url_even_on_downgrade(self):
        self.assertEqual(referer_for(self.PAGE, self.INSECURE, "unsafe-url"), self.FULL)

    def test_no_referrer_sends_nothing_even_same_origin(self):
        self.assertIsNone(referer_for(self.PAGE, self.SAME, "no-referrer"))

    def test_origin_sends_only_the_origin_even_on_downgrade(self):
        self.assertEqual(referer_for(self.PAGE, self.INSECURE, "origin"), self.ORIGIN)

    def test_no_referrer_when_downgrade_sends_nothing_from_https_to_http(self):
        self.assertIsNone(referer_for(self.PAGE, self.INSECURE, "no-referrer-when-downgrade"))

    def test_strict_origin_sends_origin_cross_origin_and_nothing_on_downgrade(self):
        self.assertEqual(referer_for(self.PAGE, self.CROSS, "strict-origin"), self.ORIGIN)
        self.assertIsNone(referer_for(self.PAGE, self.INSECURE, "strict-origin"))

    def test_same_origin_sends_full_url_only_to_same_origin(self):
        self.assertEqual(referer_for(self.PAGE, self.SAME, "same-origin"), self.FULL)
        self.assertIsNone(referer_for(self.PAGE, self.CROSS, "same-origin"))

    def test_default_policy_sends_full_same_origin_origin_cross_and_nothing_on_downgrade(self):
        policy = "strict-origin-when-cross-origin"
        self.assertEqual(referer_for(self.PAGE, self.SAME, policy), self.FULL)
        self.assertEqual(referer_for(self.PAGE, self.CROSS, policy), self.ORIGIN)
        self.assertIsNone(referer_for(self.PAGE, self.INSECURE, policy))

    def test_different_port_counts_as_cross_origin(self):
        other_port = "https://accounts.shop.example:8443/x.js"
        self.assertEqual(referer_for(self.PAGE, other_port, "same-origin"), None)

    def test_http_page_to_http_vendor_is_not_a_downgrade(self):
        page = "http://legacy.shop.example/reset?token=t1"
        self.assertEqual(referer_for(page, self.INSECURE, "strict-origin"), "http://legacy.shop.example/")

    def test_over_long_url_is_cut_to_its_origin(self):
        page = f"{SITE}/reset?token={'a' * 5000}"
        self.assertEqual(referer_for(page, self.CROSS, "unsafe-url"), self.ORIGIN)

    def test_missing_or_unknown_header_falls_back_to_browser_default(self):
        self.assertEqual(parse_policy_header(None), "strict-origin-when-cross-origin")
        self.assertEqual(parse_policy_header("bogus"), "strict-origin-when-cross-origin")

    def test_last_recognised_policy_in_header_wins(self):
        self.assertEqual(parse_policy_header("no-referrer, unsafe-url, made-up"), "unsafe-url")


if __name__ == "__main__":
    unittest.main()
