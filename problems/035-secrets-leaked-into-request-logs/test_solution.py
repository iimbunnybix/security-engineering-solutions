import logging
import secrets
import unittest

from solution import (REDACTED, RedactingFilter, Request, is_sensitive_key, log_request_hotfix,
                      log_request_naive, log_request_safe, redact_value, safe_request_summary)


class ListHandler(logging.Handler):
    """Collects formatted log lines in memory, like a log shipper would send them."""

    def __init__(self):
        super().__init__()
        self.lines: list[str] = []
        self.setFormatter(logging.Formatter("%(levelname)s %(name)s %(message)s"))

    def emit(self, record):
        self.lines.append(self.format(record))

    def text(self) -> str:
        return "\n".join(self.lines)


class FakeSecrets:
    """Fresh fake credentials built at runtime for every test."""

    def __init__(self):
        self.password = "pw-" + secrets.token_urlsafe(12)
        self.new_password = "pw-" + secrets.token_urlsafe(12)
        self.bearer = secrets.token_urlsafe(24)
        self.query_token = secrets.token_urlsafe(24)
        self.api_key = "key-" + secrets.token_hex(16)
        self.cookie = secrets.token_hex(16)

    def all(self) -> list[str]:
        return [self.password, self.new_password, self.bearer, self.query_token,
                self.api_key, self.cookie]


def login_request(fake: FakeSecrets) -> Request:
    return Request(
        method="POST",
        url=f"/v1/statements?month=2026-10&access_token={fake.query_token}",
        headers={"Authorization": f"Bearer {fake.bearer}", "X-Api-Key": fake.api_key,
                 "Cookie": f"sid={fake.cookie}", "User-Agent": "app/5.2"},
        body={"email": "user@example.test", "password": fake.password,
              "profile": {"new_password": fake.new_password, "city": "Pune"}},
        user_id="u-42",
    )


class LoggingTestCase(unittest.TestCase):
    def setUp(self):
        self.fake = FakeSecrets()
        self.handler = ListHandler()
        self.logger = logging.getLogger(f"api.{id(self)}")
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self.handler)

    def tearDown(self):
        self.logger.removeHandler(self.handler)

    def assert_no_secret_logged(self):
        for secret in self.fake.all():
            self.assertNotIn(secret, self.handler.text())

    def leaked(self) -> list[str]:
        return [s for s in self.fake.all() if s in self.handler.text()]


class ReproduceProblem(LoggingTestCase):
    def test_naive_logging_writes_every_secret_to_the_log(self):
        log_request_naive(self.logger, login_request(self.fake))
        self.assertEqual(self.leaked(), self.fake.all())

    def test_hotfix_removes_only_the_top_level_password(self):
        log_request_hotfix(self.logger, login_request(self.fake))
        self.assertNotIn(self.fake.password, self.handler.text())
        self.assertEqual(len(self.leaked()), len(self.fake.all()) - 1)


class FixAllowlistedSummary(LoggingTestCase):
    def test_safe_summary_logs_no_secret(self):
        log_request_safe(self.logger, login_request(self.fake))
        self.assert_no_secret_logged()

    def test_safe_summary_keeps_useful_debugging_fields(self):
        summary = safe_request_summary(login_request(self.fake))
        self.assertEqual(summary["method"], "POST")
        self.assertEqual(summary["user_id"], "u-42")
        self.assertEqual(summary["headers"], {"user-agent": "app/5.2"})
        self.assertEqual(summary["body_keys"], ["email", "password", "profile"])
        self.assertIn("month=2026-10", summary["url"])

    def test_sensitive_query_parameter_is_replaced_not_removed(self):
        summary = safe_request_summary(login_request(self.fake))
        self.assertIn("access_token=[REDACTED]", summary["url"])


class FixRedactingFilter(LoggingTestCase):
    def setUp(self):
        super().setUp()
        self.handler.addFilter(RedactingFilter())

    def test_filter_protects_even_the_naive_middleware(self):
        log_request_naive(self.logger, login_request(self.fake))
        self.assert_no_secret_logged()
        self.assertIn("Pune", self.handler.text())   # non-secret data survives

    def test_filter_protects_the_hotfix_middleware(self):
        log_request_hotfix(self.logger, login_request(self.fake))
        self.assert_no_secret_logged()

    def test_secret_in_hand_written_message_is_redacted(self):
        self.logger.warning(f"retrying login with password={self.fake.password}")
        self.assert_no_secret_logged()
        self.assertIn(f"password={REDACTED}", self.handler.text())

    def test_bearer_token_in_message_argument_is_redacted(self):
        self.logger.info("upstream rejected %s", f"Authorization: Bearer {self.fake.bearer}")
        self.assert_no_secret_logged()

    def test_dict_style_arguments_are_redacted(self):
        self.logger.info("login %(user)s %(password)s", {"user": "u-42", "password": self.fake.password})
        self.assert_no_secret_logged()
        self.assertIn("u-42", self.handler.text())

    def test_secret_in_exception_traceback_is_redacted(self):
        try:
            raise ValueError(f"bad credentials token={self.fake.query_token}")
        except ValueError:
            self.logger.exception("login failed")
        self.assertIn("ValueError", self.handler.text())
        self.assert_no_secret_logged()


class SensitiveKeyNames(unittest.TestCase):
    def test_key_name_variants_are_recognised(self):
        for key in ("password", "Password", "new_password", "X-Api-Key", "apiKey",
                    "refreshToken", "client_secret", "Set-Cookie", "Authorization"):
            self.assertTrue(is_sensitive_key(key), key)

    def test_ordinary_key_names_are_not_redacted(self):
        for key in ("email", "city", "shipping_address", "amount", "user_id"):
            self.assertFalse(is_sensitive_key(key), key)

    def test_nested_lists_and_dicts_are_redacted(self):
        value = {"items": [{"card_token": "t1", "qty": 2}], "meta": ("ok", {"secret": "s"})}
        self.assertEqual(redact_value(value),
                         {"items": [{"card_token": REDACTED, "qty": 2}],
                          "meta": ("ok", {"secret": REDACTED})})

    def test_redaction_does_not_modify_the_original_object(self):
        body = {"password": "p"}
        redact_value(body)
        self.assertEqual(body, {"password": "p"})


if __name__ == "__main__":
    unittest.main()
