import unittest

from solution import (CSP_HEADER, XFO_HEADER, can_be_framed, merge_into_csp,
                      naive_response_headers, protected_response_headers)

SETTINGS_PAGE = "https://app.example.com/settings/delete-account"
OWN_PAGE = "https://app.example.com/help"
ATTACKER_PAGE = "https://prize-claim.example.net/win"
PARTNER = "https://partner.example.org"
EXISTING_CSP = {CSP_HEADER: "default-src 'self'; script-src 'self'"}


class ReproduceProblem(unittest.TestCase):
    def test_attacker_site_can_frame_the_delete_account_page(self):
        headers = naive_response_headers({})
        self.assertTrue(can_be_framed(headers, SETTINGS_PAGE, ATTACKER_PAGE))

    def test_an_existing_csp_without_frame_ancestors_does_not_protect(self):
        headers = naive_response_headers(EXISTING_CSP)
        self.assertTrue(can_be_framed(headers, SETTINGS_PAGE, ATTACKER_PAGE))

    def test_allow_from_is_ignored_by_modern_browsers(self):
        headers = {XFO_HEADER: f"ALLOW-FROM {PARTNER}"}
        self.assertTrue(can_be_framed(headers, SETTINGS_PAGE, ATTACKER_PAGE))


class FixFrameAncestors(unittest.TestCase):
    def test_attacker_site_cannot_frame_the_page(self):
        headers = protected_response_headers({})
        self.assertFalse(can_be_framed(headers, SETTINGS_PAGE, ATTACKER_PAGE))

    def test_our_own_pages_can_still_frame_it(self):
        headers = protected_response_headers({})
        self.assertTrue(can_be_framed(headers, SETTINGS_PAGE, OWN_PAGE))

    def test_explicit_partner_can_embed_but_others_cannot(self):
        headers = protected_response_headers({}, allowed_embedders=[PARTNER])
        self.assertTrue(can_be_framed(headers, SETTINGS_PAGE, PARTNER + "/dashboard"))
        self.assertFalse(can_be_framed(headers, SETTINGS_PAGE, ATTACKER_PAGE))

    def test_partner_over_plain_http_is_not_the_same_origin(self):
        headers = protected_response_headers({}, allowed_embedders=[PARTNER])
        self.assertFalse(can_be_framed(headers, SETTINGS_PAGE, "http://partner.example.org/"))

    def test_lookalike_subdomain_of_the_partner_is_rejected(self):
        headers = protected_response_headers({}, allowed_embedders=[PARTNER])
        self.assertFalse(can_be_framed(headers, SETTINGS_PAGE, "https://partner.example.org.evil.test/"))

    def test_non_https_partner_is_a_config_error(self):
        with self.assertRaises(ValueError):
            protected_response_headers({}, allowed_embedders=["http://partner.example.org"])

    def test_old_browsers_get_x_frame_options(self):
        headers = protected_response_headers({})
        self.assertEqual(headers[XFO_HEADER], "SAMEORIGIN")
        legacy_view = {XFO_HEADER: headers[XFO_HEADER]}
        self.assertFalse(can_be_framed(legacy_view, SETTINGS_PAGE, ATTACKER_PAGE))


class FixCspMerge(unittest.TestCase):
    def test_existing_directives_are_kept(self):
        headers = protected_response_headers(EXISTING_CSP)
        self.assertIn("default-src 'self'", headers[CSP_HEADER])
        self.assertIn("script-src 'self'", headers[CSP_HEADER])
        self.assertFalse(can_be_framed(headers, SETTINGS_PAGE, ATTACKER_PAGE))

    def test_permissive_frame_ancestors_is_replaced_not_duplicated(self):
        merged = merge_into_csp("frame-ancestors *; img-src *", "frame-ancestors 'self'")
        self.assertEqual(merged, "img-src *; frame-ancestors 'self'")

    def test_frame_ancestors_none_blocks_even_same_origin(self):
        headers = {CSP_HEADER: "frame-ancestors 'none'"}
        self.assertFalse(can_be_framed(headers, SETTINGS_PAGE, OWN_PAGE))

    def test_frame_ancestors_wins_over_x_frame_options(self):
        headers = {CSP_HEADER: f"frame-ancestors 'self' {PARTNER}", XFO_HEADER: "DENY"}
        self.assertTrue(can_be_framed(headers, SETTINGS_PAGE, PARTNER))


if __name__ == "__main__":
    unittest.main()
