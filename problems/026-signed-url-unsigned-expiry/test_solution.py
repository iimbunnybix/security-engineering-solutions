import os
import unittest

from solution import (
    MAX_LINK_LIFETIME_S,
    InvalidLink,
    naive_sign,
    naive_verify,
    sign_link,
    verify_link,
)

NOW = 1_790_000_000
ONE_HOUR = 3600
FAR_FUTURE = 4_070_908_800      # year 2099
PATH = "/files/invoice-17.pdf"


def new_key():
    return os.urandom(32)


def replace_expires(url, new_expires):
    path, _, query = url.partition("?")
    params = dict(pair.split("=", 1) for pair in query.split("&"))
    params["expires"] = str(new_expires)
    return path + "?" + "&".join(f"{name}={value}" for name, value in params.items())


class ReproduceProblem(unittest.TestCase):
    def test_expired_link_is_revived_by_editing_expires(self):
        key = new_key()
        link = naive_sign(key, PATH, NOW + ONE_HOUR)
        later = NOW + 2 * ONE_HOUR
        with self.assertRaises(InvalidLink):
            naive_verify(key, link, later)
        revived = replace_expires(link, FAR_FUTURE)
        self.assertEqual(naive_verify(key, revived, later), PATH)


class FixSignsTheExpiry(unittest.TestCase):
    def setUp(self):
        self.key = new_key()
        self.link = sign_link(self.key, PATH, NOW, ONE_HOUR)

    def test_valid_link_returns_the_path(self):
        self.assertEqual(verify_link(self.key, self.link, NOW + 10), PATH)

    def test_edited_expiry_is_rejected(self):
        with self.assertRaisesRegex(InvalidLink, "bad signature"):
            verify_link(self.key, replace_expires(self.link, FAR_FUTURE), NOW + 2 * ONE_HOUR)

    def test_link_expires_on_time(self):
        with self.assertRaisesRegex(InvalidLink, "expired"):
            verify_link(self.key, self.link, NOW + ONE_HOUR)

    def test_edited_path_is_rejected(self):
        other = self.link.replace("invoice-17", "invoice-18")
        with self.assertRaises(InvalidLink):
            verify_link(self.key, other, NOW)

    def test_link_signed_for_get_does_not_work_for_delete(self):
        with self.assertRaises(InvalidLink):
            verify_link(self.key, self.link, NOW, method="DELETE")

    def test_link_from_another_key_is_rejected(self):
        with self.assertRaises(InvalidLink):
            verify_link(new_key(), self.link, NOW)

    def test_path_with_spaces_round_trips(self):
        link = sign_link(self.key, "/files/my invoice.pdf", NOW, ONE_HOUR)
        self.assertEqual(verify_link(self.key, link, NOW), "/files/my invoice.pdf")


class FixParsesTheQueryStrictly(unittest.TestCase):
    def setUp(self):
        self.key = new_key()
        self.link = sign_link(self.key, PATH, NOW, ONE_HOUR)

    def test_duplicate_expires_parameter_is_rejected(self):
        with self.assertRaisesRegex(InvalidLink, "once"):
            verify_link(self.key, self.link + f"&expires={FAR_FUTURE}", NOW)

    def test_unknown_parameter_is_rejected(self):
        with self.assertRaises(InvalidLink):
            verify_link(self.key, self.link + "&download=1", NOW)

    def test_missing_signature_is_rejected(self):
        with self.assertRaises(InvalidLink):
            verify_link(self.key, PATH + f"?expires={NOW + ONE_HOUR}", NOW)

    def test_non_numeric_expiry_is_rejected(self):
        with self.assertRaises(InvalidLink):
            verify_link(self.key, replace_expires(self.link, "+99"), NOW)

    def test_non_ascii_signature_is_rejected_not_crashing(self):
        with self.assertRaises(InvalidLink):
            verify_link(self.key, PATH + f"?expires={NOW + ONE_HOUR}&sig=%C3%A9", NOW)


class FixLimitsLifetime(unittest.TestCase):
    def test_lifetime_over_the_maximum_is_refused(self):
        with self.assertRaises(ValueError):
            sign_link(new_key(), PATH, NOW, MAX_LINK_LIFETIME_S + 1)

    def test_zero_lifetime_is_refused(self):
        with self.assertRaises(ValueError):
            sign_link(new_key(), PATH, NOW, 0)


if __name__ == "__main__":
    unittest.main()
