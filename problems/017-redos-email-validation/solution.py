"""Email validation on the signup API without catastrophic regex backtracking.

The original validator used a regex with a nested quantifier, ``([...]+)+``.
On an input that almost matches (many letters, then a bad character) Python's
backtracking regex engine tries every way to split the letters between the
inner and outer ``+``, so the work doubles with each extra character and one
request can pin a CPU core. This module caps the input length first and then
checks the address structure with plain string operations and simple regexes
that have no nested quantifiers, so the work grows linearly with the length.
"""
from __future__ import annotations

import re

# RFC 5321 limits: a forward path is at most 256 octets including the angle
# brackets, which leaves 254 for the address; the local part is at most 64.
MAX_EMAIL_LENGTH = 254
MAX_LOCAL_PART_LENGTH = 64
MAX_DOMAIN_LABEL_LENGTH = 63
MIN_TOP_LEVEL_DOMAIN_LENGTH = 2

# The vulnerable pattern: the group ([...]+) is itself repeated with +.
ORIGINAL_EMAIL_PATTERN = re.compile(
    r"^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
)

# Single character classes with one quantifier each: a match attempt can only
# move forward, so checking them is linear in the length of the text.
LOCAL_PART_CHARACTERS = re.compile(r"[A-Za-z0-9_.+%-]+")
DOMAIN_LABEL_CHARACTERS = re.compile(r"[A-Za-z0-9-]+")
TOP_LEVEL_DOMAIN_CHARACTERS = re.compile(r"[A-Za-z]+")


def original_is_valid_email(address: str) -> bool:
    """The validator that shipped: correct on normal input, exponential on hostile input."""
    return ORIGINAL_EMAIL_PATTERN.match(address) is not None


def is_valid_local_part(local_part: str) -> bool:
    """Check the part before '@': allowed characters and sensible dot placement."""
    if not local_part or len(local_part) > MAX_LOCAL_PART_LENGTH:
        return False
    if LOCAL_PART_CHARACTERS.fullmatch(local_part) is None:
        return False
    # Mail servers reject leading, trailing or doubled dots in an unquoted local part.
    if local_part.startswith(".") or local_part.endswith(".") or ".." in local_part:
        return False
    return True


def is_valid_domain_label(label: str) -> bool:
    """Check one dot-separated piece of the domain, e.g. 'mail' in 'mail.example.in'."""
    if not label or len(label) > MAX_DOMAIN_LABEL_LENGTH:
        return False
    if DOMAIN_LABEL_CHARACTERS.fullmatch(label) is None:
        return False
    # DNS hostnames may not start or end with a hyphen.
    return not (label.startswith("-") or label.endswith("-"))


def is_valid_domain(domain: str) -> bool:
    """Check the part after '@': at least two labels and an alphabetic top-level domain."""
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not is_valid_domain_label(label):
            return False
    top_level = labels[-1]
    if len(top_level) < MIN_TOP_LEVEL_DOMAIN_LENGTH:
        return False
    return TOP_LEVEL_DOMAIN_CHARACTERS.fullmatch(top_level) is not None


def is_valid_email(address: str) -> bool:
    """Validate a signup email address in time linear in its (capped) length."""
    # Reject oversized input before doing any other work, so the cost of a
    # single request is bounded no matter what the attacker sends.
    if len(address) > MAX_EMAIL_LENGTH:
        return False
    if address.count("@") != 1:
        return False
    local_part, domain = address.split("@")
    return is_valid_local_part(local_part) and is_valid_domain(domain)
