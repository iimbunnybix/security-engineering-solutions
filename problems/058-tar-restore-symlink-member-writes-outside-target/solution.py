"""Restore a tenant backup tar without following symlink or hardlink members.

The "restore workspace" feature took a user-uploaded .tar and extracted it
member by member. It already refused names like "../x" or "/etc/x", but it
recreated symlink and hardlink members. An archive with a symlink
"uploads -> /srv/app" followed by a regular file "uploads/settings.py"
passes the name check, yet the file is written through the link into the
application folder. A hardlink member pointing at a server file puts that
file (same inode) inside the tenant's workspace.

``safe_restore`` extracts only regular files and directories, refuses every
link or special member, and checks the final real path of each file.
"""
from __future__ import annotations

import os
import posixpath
import tarfile
from pathlib import Path
from typing import BinaryIO

# Workspace backups only ever contain folders and plain files.
ALLOWED_MEMBER_TYPES = ("regular file", "directory")
# Never restore setuid/setgid/sticky bits or world-writable files.
SAFE_FILE_MODE = 0o644
SAFE_DIR_MODE = 0o755
COPY_CHUNK_BYTES = 64 * 1024


class UnsafeArchive(ValueError):
    """The upload contains a member we refuse to restore (HTTP 400)."""


def is_safe_member_name(name: str) -> bool:
    """Name check used by both versions: relative and without '..' parts."""
    if name.startswith("/") or "\\" in name:
        return False
    return ".." not in posixpath.normpath(name).split("/")


def _write_member_file(archive: tarfile.TarFile, member: tarfile.TarInfo, target: Path) -> None:
    """Copy one regular file's bytes from the archive to the target path."""
    source = archive.extractfile(member)
    with source, open(target, "wb") as output:
        while chunk := source.read(COPY_CHUNK_BYTES):
            output.write(chunk)


def naive_restore(archive_file: BinaryIO, destination: Path) -> None:
    """Original restore: checks member names, then recreates links as given."""
    with tarfile.open(fileobj=archive_file) as archive:
        for member in archive.getmembers():
            if not is_safe_member_name(member.name):
                raise UnsafeArchive(f"unsafe name {member.name!r}")
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.issym():
                os.symlink(member.linkname, target)
            elif member.islnk():
                # tar stores the hardlink target as a path; an absolute one
                # makes Path's "/" operator ignore the destination entirely.
                os.link(destination / member.linkname, target)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                # open() follows any symlink created by an earlier member.
                _write_member_file(archive, member, target)


def _member_type_name(member: tarfile.TarInfo) -> str:
    """Human-readable member type for allow-listing and error messages."""
    if member.isfile():
        return "regular file"
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    return "special file"


def _check_member(member: tarfile.TarInfo) -> None:
    """Raise UnsafeArchive for any member we will not restore."""
    if not is_safe_member_name(member.name):
        raise UnsafeArchive(f"unsafe name {member.name!r}")
    member_type = _member_type_name(member)
    if member_type not in ALLOWED_MEMBER_TYPES:
        raise UnsafeArchive(f"{member_type} member {member.name!r} is not allowed")


def _resolved_inside(destination_root: Path, target: Path) -> bool:
    """True if target's real path (all links resolved) is inside the root."""
    return target.resolve().is_relative_to(destination_root)


def safe_restore(archive_file: BinaryIO, destination: Path) -> list[str]:
    """Restore files and folders only; return the restored file names.

    Every member is validated before anything is written, so a bad archive
    leaves the destination untouched instead of half-restored.
    """
    destination_root = destination.resolve()
    with tarfile.open(fileobj=archive_file) as archive:
        members = archive.getmembers()
        for member in members:
            _check_member(member)
        restored: list[str] = []
        for member in members:
            target = destination_root / member.name
            # Defence in depth: the destination may already contain a link
            # (for example from a previous restore with the old code).
            if not _resolved_inside(destination_root, target):
                raise UnsafeArchive(f"{member.name!r} resolves outside the workspace")
            if member.isdir():
                target.mkdir(mode=SAFE_DIR_MODE, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=SAFE_DIR_MODE, parents=True, exist_ok=True)
            _write_member_file(archive, member, target)
            target.chmod(SAFE_FILE_MODE)
            restored.append(member.name)
    return restored
