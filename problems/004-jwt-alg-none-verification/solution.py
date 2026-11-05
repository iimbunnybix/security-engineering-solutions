"""Strict JWT (HS256) verification with the standard library.

The vulnerable pattern is letting the *token* decide how it is verified:
reading ``alg`` from the attacker-controlled header and accepting ``none``,
or skipping claim checks. ``StrictJWTVerifier`` pins the algorithm on the
server, selects the key by ``kid`` from a server-side key ring, compares
signatures in constant time and validates exp/nbf/iat/iss/aud.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Callable, Mapping


class InvalidToken(Exception):
    """Any verification failure. Keep the reason internal; return 401 to clients."""


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(seg: str) -> bytes:
    if not seg or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                      for c in seg):
        raise InvalidToken("bad base64url segment")
    # A length of 4n+1 cannot be produced by any byte string, and base64
    # raises binascii.Error for it; turn that into the uniform InvalidToken.
    if len(seg) % 4 == 1:
        raise InvalidToken("bad base64url length")
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def sign_hs256(claims: Mapping[str, Any], key: bytes, kid: str | None = None) -> str:
    header = {"alg": "HS256", "typ": "JWT", **({"kid": kid} if kid else {})}
    signing_input = (b64url_encode(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + b64url_encode(json.dumps(dict(claims), separators=(",", ":")).encode()))
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url_encode(sig)


def naive_verify(token: str, key: bytes) -> dict:
    """The original code: trusts the header's alg and never checks claims."""
    h, p, s = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    if header.get("alg", "").lower() == "none":
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    expected = b64url_encode(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest())
    if s != expected:
        raise InvalidToken("bad signature")
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


class StrictJWTVerifier:
    def __init__(self, keys: Mapping[str, bytes], issuer: str, audience: str,
                 leeway_s: int = 30, max_age_s: int | None = 3600,
                 clock: Callable[[], float] = time.time, max_token_len: int = 8192):
        if not keys:
            raise ValueError("at least one key required")
        for kid, k in keys.items():
            if len(k) < 32:      # RFC 7518 §3.2: HS256 key ≥ 256 bits
                raise ValueError(f"key {kid!r} shorter than 32 bytes")
        self.keys = dict(keys)
        self.issuer, self.audience = issuer, audience
        self.leeway, self.max_age = leeway_s, max_age_s
        self.clock, self.max_len = clock, max_token_len

    def verify(self, token: str) -> dict:
        if not isinstance(token, str) or len(token) > self.max_len:
            raise InvalidToken("token missing or too long")
        parts = token.split(".")
        if len(parts) != 3:
            raise InvalidToken("not a JWS compact token")
        h_seg, p_seg, s_seg = parts
        try:
            header = json.loads(b64url_decode(h_seg))
        except (ValueError, InvalidToken) as e:
            raise InvalidToken("bad header") from e
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            raise InvalidToken("algorithm not allowed")          # blocks none / RS256 / hs256
        if "crit" in header:
            raise InvalidToken("critical header extensions unsupported")
        kid = header.get("kid")
        key = self.keys.get(kid) if kid is not None else (
            next(iter(self.keys.values())) if len(self.keys) == 1 else None)
        if key is None:
            raise InvalidToken("unknown key id")
        expected = hmac.new(key, f"{h_seg}.{p_seg}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64url_decode(s_seg)):
            raise InvalidToken("bad signature")
        # Only parse the payload after the signature checks out.
        try:
            claims = json.loads(b64url_decode(p_seg))
        except ValueError as e:
            raise InvalidToken("bad payload") from e
        if not isinstance(claims, dict):
            raise InvalidToken("payload must be an object")
        self._check_claims(claims)
        return claims

    def _check_claims(self, c: dict) -> None:
        now = self.clock()
        for name in ("exp", "iat"):
            if not isinstance(c.get(name), (int, float)) or isinstance(c.get(name), bool):
                raise InvalidToken(f"missing or invalid {name}")
        if now > c["exp"] + self.leeway:
            raise InvalidToken("token expired")
        if "nbf" in c and now + self.leeway < c["nbf"]:
            raise InvalidToken("token not yet valid")
        if c["iat"] > now + self.leeway:
            raise InvalidToken("issued in the future")
        if self.max_age is not None and now - c["iat"] > self.max_age + self.leeway:
            raise InvalidToken("token too old")
        if c.get("iss") != self.issuer:
            raise InvalidToken("wrong issuer")
        aud = c.get("aud")
        if not (aud == self.audience or (isinstance(aud, list) and self.audience in aud)):
            raise InvalidToken("wrong audience")
