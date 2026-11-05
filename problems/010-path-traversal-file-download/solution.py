"""Serve user-requested export files without path traversal.

The original handler joined the ``file`` query parameter onto the export
directory and opened the result. ``../`` sequences, absolute paths (which make
``os.path.join`` discard the base entirely), a second URL-decoding step and
symlinks (and hard links) all let a caller read files outside the directory. A later
"fix" stripped ``../`` once, which ``....//`` defeats.

``safe_resolve`` validates the name, resolves it to a real path (following
symlinks) and only accepts it if the result is a regular file inside the
caller's own tenant directory. After opening, the fd must be a regular file
with a single link, which rejects hard links that ``resolve()`` cannot see.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from urllib.parse import unquote


class Forbidden(Exception):
    """Maps to HTTP 404 for the client (do not reveal whether the file exists)."""


# ------------------------------------------------------------- vulnerable
def download_vulnerable(base_dir: str, raw_name: str) -> bytes:
    """Original handler. ``raw_name`` is the query value as the framework decoded it."""
    name = unquote(raw_name)                      # "just in case" second decode
    with open(os.path.join(base_dir, name), "rb") as fh:
        return fh.read()


def download_blocklist(base_dir: str, raw_name: str) -> bytes:
    """First attempted fix: remove '../' once. Bypassed by '....//'."""
    name = unquote(raw_name).replace("../", "")
    if name.startswith("/"):
        name = name.lstrip("/")
    with open(os.path.join(base_dir, name), "rb") as fh:
        return fh.read()


# ------------------------------------------------------------------ fixed
MAX_NAME = 255


def validate_name(name: str) -> str:
    """Reject names that cannot be legitimate export file names.

    No decoding happens here: the framework has already decoded the query
    string once, and decoding again is how double-encoding attacks work.
    """
    if not name or len(name) > MAX_NAME:
        raise Forbidden("bad length")
    if "\x00" in name or "\\" in name:
        raise Forbidden("bad character")
    if name.startswith("/") or os.path.isabs(name):
        raise Forbidden("absolute path")
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise Forbidden("dot or empty segment")
    return name


def safe_resolve(base_dir: str | Path, tenant_id: str, name: str) -> Path:
    """Return the real path of ``name`` inside ``base_dir/tenant_id`` or raise Forbidden.

    The containment check runs on the fully resolved path, so symlinks that
    point outside the tenant directory are rejected even if the name looks clean.
    """
    validate_name(name)
    if not tenant_id.isalnum():
        raise Forbidden("bad tenant")
    root = (Path(base_dir) / tenant_id).resolve(strict=True)
    try:
        target = (root / name).resolve(strict=True)
    except (FileNotFoundError, NotADirectoryError, RuntimeError) as exc:  # missing / loop
        raise Forbidden("not found") from exc
    if not target.is_relative_to(root):
        raise Forbidden("outside tenant directory")
    if not target.is_file():
        raise Forbidden("not a regular file")
    return target


def check_opened_file(fd: int) -> None:
    """Raise Forbidden unless the opened fd is a regular file with exactly one link.

    Checks run on the fd (not the path), so they describe what was really opened.
    A hard link has no target to resolve, so ``resolve()`` cannot see that it
    shares its inode with ``config/app.env``; ``st_nlink > 1`` reveals it.
    Export files are written by the app and are never legitimately hard-linked.
    """
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode):
        raise Forbidden("not a regular file")
    if info.st_nlink != 1:
        raise Forbidden("hard link")


def download_safe(base_dir: str | Path, tenant_id: str, name: str) -> bytes:
    path = safe_resolve(base_dir, tenant_id, name)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)   # refuse a symlink swapped in late
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        check_opened_file(fh.fileno())
        return fh.read()


def handle_download(base_dir: str | Path, tenant_id: str, name: str) -> tuple[int, bytes]:
    """HTTP-style handler: (status, body). Every rejection looks like 'not found'."""
    try:
        return 200, download_safe(base_dir, tenant_id, name)
    except (Forbidden, OSError, ValueError):
        return 404, b"not found"
