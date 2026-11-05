import os
import unittest

from solution import AccountApp, CsrfProtection, Request, _origin_of

APP = "https://bank.example"


class Base(unittest.TestCase):
    def setUp(self):
        self.csrf = CsrfProtection(os.urandom(32), {APP})
        self.app = AccountApp(self.csrf)
        self.sid = self.app.sessions.login("victim")
        self.app.emails["victim"] = "victim@mail.example"

    def attacker_request(self, **extra_headers):
        """What the browser sends when evil.example auto-submits a hidden form."""
        headers = {"Origin": "https://evil.example", **extra_headers}
        return Request("POST", "/account/email", headers=headers,
                       cookies={"session": self.sid},   # browser attaches it
                       form={"email": "attacker@evil.example"})

    def legit_request(self, **form):
        return Request("POST", "/account/email",
                       headers={"Origin": APP},
                       cookies={"session": self.sid},
                       form={"email": "new@mail.example",
                             "csrf_token": self.csrf.token_for(self.sid), **form})


class ReproduceCsrf(Base):
    def test_unprotected_endpoint_accepts_cross_site_form(self):
        r = self.app.change_email_unsafe(self.attacker_request())
        self.assertEqual(r.status, 200)
        self.assertEqual(self.app.emails["victim"], "attacker@evil.example")


class Protected(Base):
    def assertBlocked(self, req, reason):
        r = self.app.change_email_safe(req)
        self.assertEqual(r.status, 403)
        self.assertIn(reason, r.body)
        self.assertEqual(self.app.emails["victim"], "victim@mail.example")

    def test_cross_site_form_is_blocked(self):
        self.assertBlocked(self.attacker_request(), "cross-origin")

    def test_legit_same_origin_request_works(self):
        self.assertEqual(self.app.change_email_safe(self.legit_request()).status, 200)
        self.assertEqual(self.app.emails["victim"], "new@mail.example")

    def test_header_token_for_spa(self):
        req = self.legit_request()
        tok = req.form.pop("csrf_token")
        req.headers["X-CSRF-Token"] = tok
        self.assertEqual(self.app.change_email_safe(req).status, 200)

    def test_same_origin_without_token_is_blocked(self):
        req = self.legit_request()
        del req.form["csrf_token"]
        self.assertBlocked(req, "bad CSRF token")

    def test_token_from_another_session_is_rejected(self):
        attacker_sid = self.app.sessions.login("attacker")
        req = self.legit_request(csrf_token=self.csrf.token_for(attacker_sid))
        self.assertBlocked(req, "bad CSRF token")

    def test_token_from_other_key_is_rejected(self):
        other = CsrfProtection(os.urandom(32), {APP})
        self.assertBlocked(self.legit_request(csrf_token=other.token_for(self.sid)),
                           "bad CSRF token")

    def test_missing_origin_and_referer_is_rejected(self):
        req = self.legit_request()
        req.headers = {}
        self.assertBlocked(req, "missing Origin/Referer")

    def test_referer_fallback_and_null_origin(self):
        req = self.legit_request()
        req.headers = {"Origin": "null", "Referer": APP + "/settings?tab=email"}
        self.assertEqual(self.app.change_email_safe(req).status, 200)
        req.headers = {"Origin": "null"}
        self.assertEqual(self.app.change_email_safe(req).status, 403)

    def test_lookalike_origins_are_rejected(self):
        for o in ("https://bank.example.evil.example", "http://bank.example",
                  "https://bank.example:8443", "https://evilbank.example",
                  "javascript:alert(1)"):
            with self.subTest(o=o):
                req = self.legit_request()
                req.headers = {"Origin": o}
                self.assertBlocked(req, "cross-origin")

    def test_safe_methods_skip_checks(self):
        self.assertIsNone(self.csrf.check(Request("GET", "/account")))

    def test_header_names_are_case_insensitive(self):
        req = self.legit_request()
        req.headers = {"origin": APP}
        self.assertEqual(self.app.change_email_safe(req).status, 200)


class MalformedOriginPorts(Base):
    def request_with_origin(self, origin):
        return Request("POST", "/account/email", headers={"Origin": origin},
                       cookies={"session": self.sid},
                       form={"email": "x@mail.example",
                             "csrf_token": self.csrf.token_for(self.sid)})

    def test_out_of_range_origin_port_is_blocked_with_403(self):
        r = self.app.change_email_safe(self.request_with_origin(APP + ":99999"))
        self.assertEqual(r.status, 403)
        self.assertIn("cross-origin", r.body)

    def test_non_numeric_origin_port_is_blocked_with_403(self):
        r = self.app.change_email_safe(self.request_with_origin(APP + ":abc"))
        self.assertEqual(r.status, 403)

    def test_non_numeric_referer_port_is_blocked_with_403(self):
        req = Request("POST", "/account/email", headers={"Referer": APP + ":abc/settings"},
                      cookies={"session": self.sid})
        self.assertEqual(self.app.change_email_safe(req).status, 403)

    def test_malformed_port_normalises_to_none(self):
        self.assertIsNone(_origin_of("https://bank.example:99999"))


class Config(unittest.TestCase):
    def test_short_key_rejected(self):
        with self.assertRaises(ValueError):
            CsrfProtection(b"short", {APP})

    def test_origin_normalization(self):
        self.assertEqual(_origin_of("HTTPS://Bank.Example:443/x"), APP)
        self.assertIsNone(_origin_of("ftp://bank.example"))
        with self.assertRaises(ValueError):
            CsrfProtection(os.urandom(32), {"bank.example"})


if __name__ == "__main__":
    unittest.main()
