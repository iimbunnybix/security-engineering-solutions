import hashlib
import hmac
import json
import secrets
import unittest

from solution import (InvalidToken, StrictJWTVerifier, b64url_encode, naive_verify,
                      sign_hs256)


class Clock:
    def __init__(self, t=1_800_000_000):
        self.t = t

    def __call__(self):
        return self.t


def seg(obj):
    return b64url_encode(json.dumps(obj).encode())


class JWTTests(unittest.TestCase):
    def setUp(self):
        self.key = secrets.token_bytes(32)          # generated at runtime, never a literal
        self.clock = Clock()
        self.v = StrictJWTVerifier({"k1": self.key}, issuer="auth.example", audience="api",
                                   clock=self.clock)
        now = self.clock.t
        self.claims = {"sub": "user-42", "role": "user", "iss": "auth.example", "aud": "api",
                       "iat": now, "exp": now + 900}

    def tok(self, **over):
        return sign_hs256({**self.claims, **over}, self.key, kid="k1")

    def none_token(self, **claims):
        return f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg({**self.claims, **claims})}."

    # --- reproduce the incident -------------------------------------------
    def test_naive_accepts_alg_none_admin_token(self):
        forged = self.none_token(role="admin")
        self.assertEqual(naive_verify(forged, self.key)["role"], "admin")

    def test_naive_accepts_expired_token(self):
        self.assertEqual(naive_verify(self.tok(exp=self.clock.t - 86400), self.key)["sub"],
                         "user-42")

    # --- the fix ------------------------------------------------------------
    def test_valid_token(self):
        self.assertEqual(self.v.verify(self.tok())["sub"], "user-42")

    def test_alg_none_and_variants_rejected(self):
        for alg in ("none", "None", "NONE", "nOnE"):
            t = f"{seg({'alg': alg})}.{seg(self.claims)}."
            with self.assertRaises(InvalidToken, msg=alg):
                self.v.verify(t)

    def test_alg_confusion_rejected(self):
        # attacker signs with HMAC but labels RS256 / lower-case variants
        for alg in ("RS256", "hs256", "HS512"):
            h, p = seg({"alg": alg, "kid": "k1"}), seg(self.claims)
            sig = b64url_encode(hmac.new(self.key, f"{h}.{p}".encode(), hashlib.sha256).digest())
            with self.assertRaises(InvalidToken, msg=alg):
                self.v.verify(f"{h}.{p}.{sig}")

    def test_tampered_payload_rejected(self):
        h, _, s = self.tok().split(".")
        with self.assertRaises(InvalidToken):
            self.v.verify(f"{h}.{seg({**self.claims, 'role': 'admin'})}.{s}")

    def test_wrong_key_rejected(self):
        t = sign_hs256(self.claims, secrets.token_bytes(32), kid="k1")
        with self.assertRaises(InvalidToken):
            self.v.verify(t)

    def test_expiry_with_leeway(self):
        t = self.tok(exp=self.clock.t)
        self.clock.t += 30
        self.assertTrue(self.v.verify(t))            # within 30 s leeway
        self.clock.t += 1
        with self.assertRaises(InvalidToken):
            self.v.verify(t)

    def test_nbf_and_future_iat(self):
        with self.assertRaises(InvalidToken):
            self.v.verify(self.tok(nbf=self.clock.t + 120))
        with self.assertRaises(InvalidToken):
            self.v.verify(self.tok(iat=self.clock.t + 120))

    def test_long_lived_token_rejected_by_max_age(self):
        t = self.tok(exp=self.clock.t + 10 * 86400)
        self.clock.t += 2 * 3600
        with self.assertRaises(InvalidToken):
            self.v.verify(t)

    def test_issuer_and_audience(self):
        for over in ({"iss": "evil"}, {"aud": "other-api"}, {"aud": ["x", "y"]}):
            with self.assertRaises(InvalidToken, msg=over):
                self.v.verify(self.tok(**over))
        self.assertTrue(self.v.verify(self.tok(aud=["billing", "api"])))

    def test_missing_or_bad_claims(self):
        bad = dict(self.claims)
        del bad["exp"]
        with self.assertRaises(InvalidToken):
            self.v.verify(sign_hs256(bad, self.key, kid="k1"))
        with self.assertRaises(InvalidToken):
            self.v.verify(self.tok(exp="never"))
        with self.assertRaises(InvalidToken):
            self.v.verify(self.tok(exp=True))

    def test_key_rotation_by_kid(self):
        new_key = secrets.token_bytes(32)
        v = StrictJWTVerifier({"k1": self.key, "k2": new_key}, "auth.example", "api",
                              clock=self.clock)
        self.assertTrue(v.verify(sign_hs256(self.claims, new_key, kid="k2")))
        self.assertTrue(v.verify(self.tok()))
        with self.assertRaises(InvalidToken):
            v.verify(sign_hs256(self.claims, new_key, kid="k9"))
        with self.assertRaises(InvalidToken):              # ambiguous: no kid, 2 keys
            v.verify(sign_hs256(self.claims, new_key))

    def test_malformed_tokens(self):
        for t in ("", "a.b", "a.b.c.d", "!!!.x.y", "x" * 9000, None,
                  f"{seg([1, 2])}.{seg(self.claims)}.sig"):
            with self.assertRaises(InvalidToken, msg=repr(t)[:30]):
                self.v.verify(t)

    def test_signature_with_impossible_base64_length_is_rejected(self):
        header_seg, payload_seg, _ = self.tok().split(".")
        # A 1-character segment can never be valid base64 (length % 4 == 1).
        with self.assertRaises(InvalidToken):
            self.v.verify(f"{header_seg}.{payload_seg}.A")

    def test_non_string_kid_is_rejected(self):
        for bad_kid in (["k1"], {}, 7):
            token = f"{seg({'alg': 'HS256', 'kid': bad_kid})}.{seg(self.claims)}.sig"
            with self.assertRaises(InvalidToken, msg=repr(bad_kid)):
                self.v.verify(token)

    def test_weak_key_refused(self):
        with self.assertRaises(ValueError):
            StrictJWTVerifier({"k": secrets.token_bytes(16)}, "i", "a")


if __name__ == "__main__":
    unittest.main()
