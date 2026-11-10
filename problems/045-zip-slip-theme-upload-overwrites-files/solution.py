"""Safe extraction of user-uploaded ZIP archives ("zip slip").

A site builder let customers upload a theme as a ZIP file and extracted every
member to ``themes/<customer>/`` by joining the member's name onto that folder.
Member names come from the archive, so a name like ``../../app/config.py`` or
``/etc/cron.d/job`` wrote files outside the theme folder. This module checks
every member's resolved destination against the target folder before writing
anything, and rejects absolute paths, drive letters, symlinks and too many
members, so a hostile archive is refused as a whole instead of half-extracted.
"""
from __future__ import annotations

import os
import stat
import zipfile
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 2_000
# Upper 16 bits of external_attr hold the Unix mode for archives made on Unix.
UNIX_MODE_SHIFT = 16


class UnsafeArchive(Exception):
    """Raised when an archive would write outside its folder; nothing is written."""


# --------------------------------------------------------------------------
# ORIGINAL extraction
# --------------------------------------------------------------------------

def naive_extract(archive: zipfile.ZipFile, target_folder: Path) -> list[Path]:
    """ORIGINAL: joins each member name onto the folder and writes it."""
    written = []
    for member in archive.infolist():
        if member.is_dir():
            continue
        # The bug: the name is trusted, so "../" or an absolute path escapes.
        destination = Path(os.path.join(target_folder, member.filename))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(archive.read(member))
        written.append(destination)
    return written


# --------------------------------------------------------------------------
# FIX: validate every destination first, then write
# --------------------------------------------------------------------------

def is_symlink_member(member: zipfile.ZipInfo) -> bool:
    """True if the member was stored as a Unix symbolic link.

    A symlink pointing outside the folder lets a *later* member be written
    through it, so links are refused instead of followed.
    """
    unix_mode = member.external_attr >> UNIX_MODE_SHIFT
    return stat.S_ISLNK(unix_mode)


def check_member_name(name: str) -> None:
    """Reject names that are absolute or carry a Windows drive or backslash."""
    if name.startswith("/") or name.startswith("\\"):
        raise UnsafeArchive(f"absolute path: {name!r}")
    # "C:evil" or "C:\\evil" is absolute on Windows even without a slash.
    if len(name) >= 2 and name[1] == ":":
        raise UnsafeArchive(f"drive letter: {name!r}")
    # Backslashes are separators on Windows, so "..\\x" escapes there.
    if "\\" in name:
        raise UnsafeArchive(f"backslash in name: {name!r}")
    if "\x00" in name:
        raise UnsafeArchive(f"NUL byte in name: {name!r}")


def safe_destination(target_folder: Path, name: str) -> Path:
    """Return where a member would land, or raise if that is outside the folder."""
    check_member_name(name)
    resolved_root = target_folder.resolve()
    # resolve() collapses "..", and follows symlinks already on disk, so the
    # comparison is made on the real final location, not on the string.
    destination = (resolved_root / PurePosixPath(name)).resolve()
    if destination != resolved_root and resolved_root not in destination.parents:
        raise UnsafeArchive(f"escapes target folder: {name!r}")
    return destination


def plan_extraction(archive: zipfile.ZipFile, target_folder: Path) -> list[tuple[zipfile.ZipInfo, Path]]:
    """Validate the whole archive and return (member, destination) pairs.

    Checking everything before writing anything means a rejected archive
    leaves no partial theme behind.
    """
    members = archive.infolist()
    if len(members) > MAX_MEMBERS:
        raise UnsafeArchive(f"too many members: {len(members)}")
    plan = []
    for member in members:
        if is_symlink_member(member):
            raise UnsafeArchive(f"symlink member: {member.filename!r}")
        destination = safe_destination(target_folder, member.filename)
        if not member.is_dir():
            plan.append((member, destination))
    return plan


def safe_extract(archive: zipfile.ZipFile, target_folder: Path) -> list[Path]:
    """Extract an untrusted archive, refusing it entirely if any member is unsafe."""
    target_folder.mkdir(parents=True, exist_ok=True)
    plan = plan_extraction(archive, target_folder)
    written = []
    for member, destination in plan:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(archive.read(member))
        written.append(destination)
    return written
