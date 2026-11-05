import os
import secrets
import tempfile
import unittest
from pathlib import Path

from solution import (InvalidToken, KeyEntry, Keyring, b64url_encode, naive_verify, sign,
                      verify)

NOW = 1_800_000_000.0
ONE_HOUR = 3600


def fake_clock() -> float:
    return NOW


def user_claims(**overrides) -> dict:
    claims = {"sub": "u-1001", "role": "viewer", "exp": NOW + ONE_HOUR}
    claims.update(overrides)
    return claims


def admin_claims() -> dict:
    return user_claims(sub="attacker", role="admin")


class AppLayout:
    """<tmp>/app/keys/<kid> holds real keys; <tmp>/app/static/app.css is public."""

    def __init__(self, root: Path):
        self.keys_dir = root / "app" / "keys"
        self.static_dir = root / "app" / "static"
        self.keys_dir.mkdir(parents=True)
        self.static_dir.mkdir(parents=True)
        self.real_key = secrets.token_bytes(32)          # fake key, built at runtime
        (self.keys_dir / "2026-10").write_bytes(self.real_key)
        self.public_css = b"body { font-family: sans-serif; }\n"
        (self.static_dir / "app.css").write_bytes(self.public_css)


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.app = AppLayout(Path(self._tmp.name))
        self.keys_dir = str(self.app.keys_dir)

    def tearDown(self):
        self._tmp.cleanup()

    def test_legitimate_token_is_accepted(self):
        token = sign(user_claims(), self.app.real_key, kid="2026-10")
        self.assertEqual(naive_verify(token, self.keys_dir)["role"], "viewer")

    def test_kid_pointing_at_a_public_file_forges_an_admin_token(self):
        # The attacker downloaded /static/app.css and uses its bytes as the HMAC key.
        token = sign(admin_claims(), self.app.public_css, kid="../static/app.css")
        self.assertEqual(naive_verify(token, self.keys_dir)["role"], "admin")

    @unittest.skipUnless(os.path.exists("/dev/null"), "needs /dev/null")
    def test_kid_pointing_at_dev_null_gives_an_empty_key(self):
        token = sign(admin_claims(), b"", kid="../../../../../../../../dev/null")
        self.assertEqual(naive_verify(token, self.keys_dir)["role"], "admin")

    def test_unknown_kid_falls_back_to_the_empty_default_key(self):
        token = sign(admin_claims(), b"", kid="no-such-key")
        self.assertEqual(naive_verify(token, self.keys_dir)["role"], "admin")


class FixAllowlistedKeyring(unittest.TestCase):
    def setUp(self):
        self.current_key = secrets.token_bytes(32)
        self.previous_key = secrets.token_bytes(64)
        self.keyring = Keyring([KeyEntry("2026-10", "HS256", self.current_key),
                                KeyEntry("2026-07", "HS512", self.previous_key)])

    def assert_rejected(self, token: str, reason: str) -> None:
        with self.assertRaisesRegex(InvalidToken, reason):
            verify(token, self.keyring, clock=fake_clock)

    def test_token_signed_with_current_key_is_accepted(self):
        token = sign(user_claims(), self.current_key, kid="2026-10")
        self.assertEqual(verify(token, self.keyring, clock=fake_clock)["sub"], "u-1001")

    def test_token_signed_with_previous_key_still_works_during_rotation(self):
        token = sign(user_claims(), self.previous_key, kid="2026-07", alg="HS512")
        self.assertEqual(verify(token, self.keyring, clock=fake_clock)["sub"], "u-1001")

    def test_path_in_kid_is_rejected(self):
        token = sign(admin_claims(), b"body { font-family: sans-serif; }\n",
                     kid="../static/app.css")
        self.assert_rejected(token, "bad key id")

    def test_unknown_kid_is_rejected_without_fallback(self):
        self.assert_rejected(sign(admin_claims(), b"", kid="no-such-key"), "unknown key id")

    def test_missing_kid_is_rejected(self):
        head = b64url_encode(b'{"alg":"HS256","typ":"JWT"}')
        body = b64url_encode(b'{"role":"admin"}')
        self.assert_rejected(f"{head}.{body}.", "bad key id")

    def test_non_string_kid_is_rejected(self):
        head = b64url_encode(b'{"alg":"HS256","kid":["2026-10"]}')
        body = b64url_encode(b'{"role":"admin"}')
        self.assert_rejected(f"{head}.{body}.", "bad key id")

    def test_algorithm_not_pinned_to_the_key_is_rejected(self):
        token = sign(user_claims(), self.current_key, kid="2026-10", alg="HS512")
        self.assert_rejected(token, "algorithm does not match")

    def test_none_algorithm_is_rejected(self):
        head = b64url_encode(b'{"alg":"none","kid":"2026-10"}')
        body = b64url_encode(b'{"role":"admin"}')
        self.assert_rejected(f"{head}.{body}.", "algorithm does not match")

    def test_wrong_key_for_a_valid_kid_is_rejected(self):
        token = sign(admin_claims(), secrets.token_bytes(32), kid="2026-10")
        self.assert_rejected(token, "bad signature")

    def test_expired_token_is_rejected(self):
        token = sign(user_claims(exp=NOW - 1), self.current_key, kid="2026-10")
        self.assert_rejected(token, "expired")

    def test_garbage_token_is_rejected(self):
        for token in ("", "a.b", "not.a.jwt.at.all", "x" * 9000):
            self.assert_rejected(token, "")


class KeyringConfiguration(unittest.TestCase):
    def test_short_key_is_refused_at_startup(self):
        with self.assertRaisesRegex(ValueError, "shorter"):
            Keyring([KeyEntry("k1", "HS256", b"short")])

    def test_empty_keyring_is_refused(self):
        with self.assertRaisesRegex(ValueError, "empty"):
            Keyring([])

    def test_kid_with_path_characters_is_refused_in_config(self):
        with self.assertRaisesRegex(ValueError, "invalid characters"):
            Keyring([KeyEntry("../k1", "HS256", secrets.token_bytes(32))])

    def test_duplicate_kid_is_refused(self):
        key = secrets.token_bytes(32)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            Keyring([KeyEntry("k1", "HS256", key), KeyEntry("k1", "HS256", key)])


if __name__ == "__main__":
    unittest.main()
