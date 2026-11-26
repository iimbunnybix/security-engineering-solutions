"""An upload denylist of dangerous extensions was bypassed with spelling tricks.

The document upload checked ``filename.endswith(".php")`` (and a few other
extensions) and stored the file under the client's name in a web-served
folder. ``shell.PHP``, ``shell.php.`` (Windows and some servers drop the
trailing dot), ``shell.php5``, ``shell.phtml`` and ``shell.php::$DATA`` all
passed, and the web server executed them. The fix flips to an allowlist of
the few types the feature needs, rejects names that different systems
interpret differently, and stores the file under a random server-chosen
name with the canonical extension, so the client's spelling never reaches
the disk.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass

# Original denylist: what someone thought of on the day.
DENIED_EXTENSIONS = (".php", ".exe", ".sh", ".html", ".js")

# The feature accepts scanned documents and photos, nothing else.
ALLOWED_EXTENSIONS = {"pdf": "pdf", "png": "png", "jpg": "jpg", "jpeg": "jpg"}
STORED_NAME_BYTES = 16
MAX_FILENAME_LENGTH = 255
# Characters that mean different things to different filesystems or servers:
# NUL ends C strings, ":" opens NTFS streams, slashes are path separators.
FORBIDDEN_CHARACTERS = ("\x00", ":", "/", "\\")


class RejectedUpload(ValueError):
    """The upload is refused (HTTP 400)."""


@dataclass(frozen=True)
class StoredFile:
    stored_name: str
    original_name: str


# ---------------------------------------------------------------- original
def naive_is_allowed(filename: str) -> bool:
    """Original check: block names ending in a known-bad extension."""
    for extension in DENIED_EXTENSIONS:
        if filename.endswith(extension):
            return False
    return True


# ---------------------------------------------------------------- the fix
def _reject_ambiguous_name(filename: str) -> None:
    """Refuse names that a server or OS might read as a different name.

    Windows and IIS silently strip trailing dots and spaces, so "a.php."
    becomes "a.php" on disk; we would rather refuse than guess.
    """
    if not filename or len(filename) > MAX_FILENAME_LENGTH:
        raise RejectedUpload("missing or overlong filename")
    for character in FORBIDDEN_CHARACTERS:
        if character in filename:
            raise RejectedUpload("filename contains a forbidden character")
    if filename != filename.rstrip(". "):
        raise RejectedUpload("filename ends with a dot or space")


def canonical_extension(filename: str) -> str:
    """Return the stored extension for an allowed upload, or raise.

    Only the text after the *last* dot counts, compared case-insensitively,
    so "invoice.php.pdf" is a PDF and "photo.JPG" is a JPEG.
    """
    _reject_ambiguous_name(filename)
    stem, dot, extension = filename.rpartition(".")
    if not dot or not stem:
        raise RejectedUpload("filename has no extension")
    canonical = ALLOWED_EXTENSIONS.get(extension.lower())
    if canonical is None:
        raise RejectedUpload(f"file type .{extension} is not accepted")
    return canonical


def store_upload(filename: str) -> StoredFile:
    """Accept an upload and choose the name it is stored under.

    The random name means the client cannot pick or predict the stored path,
    and a name the client spelled cleverly is never written to disk.
    """
    extension = canonical_extension(filename)
    stored_name = f"{secrets.token_hex(STORED_NAME_BYTES)}.{extension}"
    return StoredFile(stored_name=stored_name, original_name=filename)
