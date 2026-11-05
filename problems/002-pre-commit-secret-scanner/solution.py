"""Pre-commit secret scanner: known patterns + entropy, with redacted output."""
from __future__ import annotations

import hashlib
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

RULES: dict[str, re.Pattern] = {
    "aws_access_key_id": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}
# Quoted values run to the closing quote (they may contain spaces or '#');
# only unquoted values stop at whitespace or a '#' comment.
ASSIGNMENT = re.compile(
    r"""(?i)\b([a-z0-9_]*(?:password|passwd|secret|token|api_?key|access_?key)[a-z0-9_]*)\s*[:=]\s*"""
    r"""(?:"([^"]*)"|'([^']*)'|([^\s"'#]+))""")
PLACEHOLDER = re.compile(r"(?i)^(changeme|password|example|dummy|test|xxx+|\*+|<.*>|\$\{.*\}|\{\{.*\}\}|none|null|true|false)$")
ALLOW_MARKER = "secret-scan: allow"

# Base64-style secrets use ~64 symbols and random ones score well above 4.0
# bits/char. Hex has only 16 symbols, so its ceiling is log2(16) = 4.0 and
# random hex keys score about 3.6-3.9: they need a lower, hex-specific limit.
BASE64_ENTROPY_LIMIT = 4.0
HEX_ENTROPY_LIMIT = 3.0
MIN_HEX_SECRET_LENGTH = 16
HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    masked: str
    fingerprint: str


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def looks_like_hex_secret(value: str) -> bool:
    """True for long hex strings that mix letters and digits.

    All-digit values (timeouts, IDs) are excluded, because they are rarely
    keys and would otherwise pass the lower hex entropy limit.
    """
    if len(value) < MIN_HEX_SECRET_LENGTH or not set(value) <= HEX_DIGITS:
        return False
    has_digit = any(ch.isdigit() for ch in value)
    has_letter = any(ch.isalpha() for ch in value)
    return has_digit and has_letter


def is_high_entropy(value: str) -> bool:
    """Apply the entropy limit that matches the value's alphabet."""
    if looks_like_hex_secret(value):
        return shannon_entropy(value) >= HEX_ENTROPY_LIMIT
    return shannon_entropy(value) >= BASE64_ENTROPY_LIMIT


def assigned_value(match: re.Match) -> str:
    """Return whichever value group matched: double-quoted, single-quoted or bare."""
    for group_number in (2, 3, 4):
        if match.group(group_number) is not None:
            return match.group(group_number)
    return ""


def mask(secret: str) -> str:
    return secret[:4] + "*" * max(len(secret) - 4, 4) if len(secret) > 8 else "*" * 8


def _fp(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[:16]


def scan_text(text: str, path: str = "<text>", allowlist: frozenset = frozenset()) -> list[Finding]:
    findings = []
    for n, line in enumerate(text.splitlines(), 1):
        if ALLOW_MARKER in line:
            continue
        hits: dict[str, str] = {}
        for rule, pat in RULES.items():
            for m in pat.finditer(line):
                hits[m.group(0)] = rule
        for m in ASSIGNMENT.finditer(line):
            value = assigned_value(m)
            if value in hits or PLACEHOLDER.match(value) or len(value) < 8:
                continue
            if is_high_entropy(value) or len(value) >= 12 and "password" in m.group(1).lower():
                hits[value] = "high_entropy_assignment"
        for secret, rule in hits.items():
            fp = _fp(secret)
            if fp not in allowlist:
                findings.append(Finding(path, n, rule, mask(secret), fp))
    return findings


def scan_paths(paths: list[str], allowlist: frozenset = frozenset()) -> list[Finding]:
    out = []
    for p in paths:
        try:
            text = Path(p).read_text(encoding="utf-8")
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue                                          # binary or deleted file
        out.extend(scan_text(text, p, allowlist))
    return out


def main(argv: list[str]) -> int:
    allow_file = Path(".secretscan-allowlist")
    allow = frozenset(allow_file.read_text().split()) if allow_file.exists() else frozenset()
    findings = scan_paths(argv, allow)
    for f in findings:
        print(f"{f.path}:{f.line}: [{f.rule}] {f.masked}  (fingerprint {f.fingerprint})")
    if findings:
        print(f"\n{len(findings)} possible secret(s). Commit blocked. "
              "If a finding is a false positive, add its fingerprint to .secretscan-allowlist.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
