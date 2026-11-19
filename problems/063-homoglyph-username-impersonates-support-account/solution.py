"""Stop look-alike usernames such as "suppоrt" (Cyrillic "о") from being registered.

The community marketplace reserved names like "support" and kept usernames
unique case-insensitively. Scammers registered "suppоrt" with a Cyrillic
"о", "ѕupport" with a Cyrillic "ѕ" and "support" with an invisible
zero-width space inside it. All passed, because to the computer they are
different strings, while to buyers they look identical. The fake support
accounts messaged buyers and collected "verification payments".

The fix compares usernames by a *skeleton*: Unicode-normalise (NFKC),
case-fold, delete invisible format characters, and map common look-alike
letters and digits to the Latin letter they imitate. A new name is refused
if its skeleton matches a reserved name or an existing user's skeleton, and
names that mix scripts (Latin with Cyrillic, say) are refused outright.
"""
from __future__ import annotations

import unicodedata

RESERVED_NAMES = {"admin", "support", "security", "help", "official"}

# A small subset of Unicode's confusables list (UTS #39), enough to show the
# idea: each character maps to the Latin letter it is mistaken for.
CONFUSABLE_TO_LATIN = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",  # Cyrillic
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l",            # Cyrillic
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "ρ": "p", "τ": "t", "κ": "k",  # Greek
    "0": "o", "1": "l",                                                     # digits
}
# Characters that belong to no script and may appear in any username.
SCRIPT_NEUTRAL = set("0123456789_-.")


class UsernameRejected(ValueError):
    """The username is reserved, taken, or could be mistaken for one that is."""


def naive_is_available(username: str, existing: set[str]) -> bool:
    """The original check: case-insensitive equality only."""
    folded = username.casefold()
    if folded in RESERVED_NAMES:
        return False
    for taken in existing:
        if taken.casefold() == folded:
            return False
    return True


def remove_invisible(text: str) -> str:
    """Drop format characters (zero-width space/joiner, bidi marks): they display as nothing."""
    visible = []
    for char in text:
        if unicodedata.category(char) != "Cf":
            visible.append(char)
    return "".join(visible)


def skeleton(username: str) -> str:
    """What the name looks like, reduced to plain Latin letters where possible.

    NFKC turns "ｓｕｐｐｏｒｔ" (full-width) into "support"; case-folding makes
    "Support" equal to "support"; then look-alikes are mapped.
    """
    text = unicodedata.normalize("NFKC", username).casefold()
    text = remove_invisible(text)
    mapped = []
    for char in text:
        mapped.append(CONFUSABLE_TO_LATIN.get(char, char))
    return "".join(mapped)


def script_of(char: str) -> str:
    """Script name taken from the Unicode character name, e.g. "LATIN", "CYRILLIC"."""
    name = unicodedata.name(char, "UNKNOWN")
    return name.split(" ")[0]


def scripts_used(username: str) -> set[str]:
    """The set of scripts in a name, ignoring digits and punctuation."""
    scripts = set()
    for char in unicodedata.normalize("NFKC", remove_invisible(username)):
        if char not in SCRIPT_NEUTRAL:
            scripts.add(script_of(char))
    return scripts


class UsernameRegistry:
    """Registered users, indexed by skeleton so look-alikes collide."""

    def __init__(self) -> None:
        self._owner_by_skeleton: dict[str, str] = {}
        self._reserved_skeletons = {skeleton(name) for name in RESERVED_NAMES}

    def check(self, username: str) -> None:
        """Raise UsernameRejected with a reason, or return if the name is fine."""
        if remove_invisible(username) != username:
            raise UsernameRejected("username contains invisible characters")
        if len(scripts_used(username)) > 1:
            raise UsernameRejected("username mixes letters from different alphabets")
        name_skeleton = skeleton(username)
        if name_skeleton in self._reserved_skeletons:
            raise UsernameRejected("username looks like a reserved name")
        if name_skeleton in self._owner_by_skeleton:
            owner = self._owner_by_skeleton[name_skeleton]
            raise UsernameRejected(f"username looks like existing user {owner!r}")

    def register(self, username: str) -> None:
        """Check, then store the name exactly as the user typed it."""
        self.check(username)
        self._owner_by_skeleton[skeleton(username)] = username
