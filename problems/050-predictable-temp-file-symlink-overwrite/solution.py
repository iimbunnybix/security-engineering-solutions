"""Predictable temp file names in a shared /tmp let a local user hijack the write.

The report exporter (running as a privileged service account) wrote each
report to f"/tmp/report-{user_id}.csv" with open(path, "w"). Any local user
could create that path first: as a symlink, so the service overwrote a file
the attacker could not touch, or as a world-readable file the attacker owned,
so customer data was written into the attacker's file. The fix creates a
private 0o700 directory with mkdtemp and the file inside it with mkstemp
(O_CREAT | O_EXCL, mode 0o600); where a fixed name is unavoidable it opens
with O_CREAT | O_EXCL | O_NOFOLLOW, which refuses any existing path.
"""
from __future__ import annotations

import csv
import io
import os
import shutil
import tempfile
from pathlib import Path

PRIVATE_DIR_PREFIX = "report-export-"
REPORT_SUFFIX = ".csv"
# Only the service account may read or write the report.
PRIVATE_FILE_MODE = 0o600
# O_NOFOLLOW does not exist on Windows; O_EXCL alone still refuses symlinks.
NO_FOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
EXCLUSIVE_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | NO_FOLLOW_FLAG

Row = tuple[str, ...]


def rows_to_csv(rows: list[Row]) -> str:
    """Render report rows as CSV text."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def predictable_report_path(shared_tmp: Path, user_id: int) -> Path:
    """The name the original code used: anyone can work it out in advance."""
    return shared_tmp / f"report-{user_id}{REPORT_SUFFIX}"


def naive_write_report(shared_tmp: Path, user_id: int, rows: list[Row]) -> Path:
    """Original code. open(..., "w") follows symlinks and reuses existing files."""
    path = predictable_report_path(shared_tmp, user_id)
    with open(path, "w", newline="") as report:
        report.write(rows_to_csv(rows))
    return path


def create_private_dir(shared_tmp: Path) -> Path:
    """Make a fresh directory only this process's user can enter.

    mkdtemp picks a random name, creates it atomically and sets mode 0o700,
    so other users can neither list it nor create files inside it.
    """
    return Path(tempfile.mkdtemp(prefix=PRIVATE_DIR_PREFIX, dir=shared_tmp))


def write_report(private_dir: Path, user_id: int, rows: list[Row]) -> Path:
    """Write a report to a new, randomly named 0o600 file in ``private_dir``.

    mkstemp opens with O_CREAT | O_EXCL, so it creates a brand-new file and
    never follows a symlink or reuses a file someone else planted.
    """
    descriptor, name = tempfile.mkstemp(prefix=f"report-{user_id}-",
                                        suffix=REPORT_SUFFIX, dir=private_dir)
    # fdopen takes ownership of the descriptor and closes it with the file.
    with os.fdopen(descriptor, "w", newline="") as report:
        report.write(rows_to_csv(rows))
    return Path(name)


def open_new_file_no_follow(path: Path) -> int:
    """Create ``path`` for writing, failing if anything already exists there.

    For when a fixed name is required. O_EXCL makes the create fail if the
    path exists, including as a dangling symlink; O_NOFOLLOW is a second
    guard. Raises FileExistsError (or OSError for a symlink on some systems).
    """
    return os.open(path, EXCLUSIVE_CREATE_FLAGS, PRIVATE_FILE_MODE)


def export_report(shared_tmp: Path, user_id: int, rows: list[Row]) -> str:
    """Full fixed flow: write the report privately, read it back, clean up."""
    private_dir = create_private_dir(shared_tmp)
    try:
        path = write_report(private_dir, user_id, rows)
        # Stands in for "upload to object storage" in the real service.
        with open(path, newline="") as report:
            return report.read()
    finally:
        # Remove the directory even if writing or uploading failed.
        shutil.rmtree(private_dir)
