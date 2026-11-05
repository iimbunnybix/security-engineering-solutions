"""Fake secrets are assembled at runtime so this file never contains a literal key."""
import os
import random
import string
import tempfile
import unittest

from solution import main, scan_text, shannon_entropy

rng = random.Random(42)


def rand(chars, n):
    return "".join(rng.choice(chars) for _ in range(n))


FAKE_KEY_ID = "AK" + "IA" + rand(string.ascii_uppercase + string.digits, 16)
FAKE_GH = "gh" + "p_" + rand(string.ascii_letters + string.digits, 36)
FAKE_SECRET = rand(string.ascii_letters + string.digits + "/+", 40)
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"


class ScannerTests(unittest.TestCase):
    def rules(self, text):
        return {f.rule for f in scan_text(text)}

    def test_detects_known_token_formats(self):
        self.assertIn("aws_access_key_id", self.rules(f"key_id = {FAKE_KEY_ID}"))
        self.assertIn("github_token", self.rules(f"TOKEN: {FAKE_GH}"))
        self.assertIn("private_key", self.rules(PEM))

    def test_detects_high_entropy_assignment_without_known_prefix(self):
        self.assertEqual(self.rules(f'AWS_SECRET_ACCESS_KEY="{FAKE_SECRET}"'), {"high_entropy_assignment"})

    def test_ignores_placeholders_and_env_references(self):
        for line in ['password = "changeme"', "api_key=${API_KEY}", "token: <your-token>",
                     "secret = xxxxxxxx", "PASSWORD=os.environ['DB_PASSWORD']"]:
            self.assertEqual(scan_text(line), [], line)

    def test_ignores_normal_code(self):
        code = "def get_token(user):\n    return cache.get(user.id)\nmax_retries = 5\n"
        self.assertEqual(scan_text(code), [])

    def test_allow_marker_and_allowlist(self):
        line = f"key = {FAKE_KEY_ID}"
        self.assertEqual(scan_text(line + "  # secret-scan: allow"), [])
        fp = scan_text(line)[0].fingerprint
        self.assertEqual(scan_text(line, allowlist=frozenset({fp})), [])

    def test_output_is_masked(self):
        f = scan_text(f"key = {FAKE_KEY_ID}")[0]
        self.assertNotIn(FAKE_KEY_ID, f.masked)
        self.assertTrue(f.masked.startswith(FAKE_KEY_ID[:4]))

    def test_entropy(self):
        self.assertLess(shannon_entropy("aaaaaaaaaaaa"), 0.1)
        self.assertGreater(shannon_entropy(FAKE_SECRET), 4.0)

    def test_cli_blocks_commit(self):
        with tempfile.TemporaryDirectory() as d:
            env = os.path.join(d, ".env")
            with open(env, "w") as fh:
                fh.write(f"DEBUG=true\nGITHUB_TOKEN={FAKE_GH}\n")
            clean = os.path.join(d, "app.py")
            with open(clean, "w") as fh:
                fh.write("print('hello')\n")
            self.assertEqual(main([clean]), 0)
            self.assertEqual(main([env, clean]), 1)


class HexKeyTests(unittest.TestCase):
    """Hex alphabets max out at 4.0 bits/char, so they need their own limit (issue #3)."""

    def test_random_hex_api_keys_are_flagged(self):
        hex_rng = random.Random(7)
        for _ in range(200):
            fake_hex_key = "".join(hex_rng.choice("0123456789abcdef") for _ in range(32))
            rules = {f.rule for f in scan_text(f"API_KEY={fake_hex_key}")}
            self.assertEqual(rules, {"high_entropy_assignment"}, fake_hex_key)

    def test_repetitive_hex_value_is_not_flagged(self):
        self.assertEqual(scan_text("token = deadbeefdeadbeef"), [])

    def test_all_digit_value_is_not_treated_as_hex(self):
        self.assertEqual(scan_text("token_ttl_ms = 86400000123456"), [])

    def test_ordinary_word_in_assignment_is_not_flagged(self):
        self.assertEqual(scan_text("token_type = authentication"), [])


if __name__ == "__main__":
    unittest.main()
