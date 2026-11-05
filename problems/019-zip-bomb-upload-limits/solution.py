"""Safe extraction of user-uploaded ZIP archives (zip bomb defence).

A bulk-import endpoint accepted a small ZIP upload and called ``read()`` on
every entry. A 1 MB "zip bomb" (highly compressible data) inflated to tens of
gigabytes and took the worker down. This module keeps that original version as
``naive_extract`` and adds ``safe_extract``, which enforces limits on entry
count, per-entry size, total size and compression ratio, and checks them while
streaming, so it stops after reading at most a little more than the limit.
"""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass

MIB = 1024 * 1024
CHUNK_BYTES = 64 * 1024
DEFAULT_MAX_ENTRIES = 1000
DEFAULT_MAX_ENTRY_BYTES = 10 * MIB
DEFAULT_MAX_TOTAL_BYTES = 50 * MIB
# Normal documents, CSVs and images compress at most ~10-20x; bombs reach 1000x.
DEFAULT_MAX_RATIO = 100
# Tiny, very repetitive files (a config of blank lines) have huge ratios but
# are harmless, so the ratio rule only applies once an entry is this big.
DEFAULT_RATIO_CHECK_MIN_BYTES = 1 * MIB


class ArchiveRejected(ValueError):
    """The upload breaks one of the extraction limits."""


@dataclass(frozen=True)
class ExtractionLimits:
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_entry_bytes: int = DEFAULT_MAX_ENTRY_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_ratio: int = DEFAULT_MAX_RATIO
    ratio_check_min_bytes: int = DEFAULT_RATIO_CHECK_MIN_BYTES


def naive_extract(archive_bytes: bytes) -> dict[str, bytes]:
    """The original code: read every entry fully into memory, no limits."""
    files = {}
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        for info in archive.infolist():
            files[info.filename] = archive.read(info)
    return files


def check_declared_sizes(entries: list[zipfile.ZipInfo], limits: ExtractionLimits) -> None:
    """Cheap first pass using the sizes the archive claims, before inflating anything.

    These header values are attacker-controlled, so passing this check is not
    enough; the streaming check below counts the real bytes as well.
    """
    if len(entries) > limits.max_entries:
        raise ArchiveRejected(f"too many entries: {len(entries)} > {limits.max_entries}")
    declared_total = 0
    for info in entries:
        if info.file_size > limits.max_entry_bytes:
            raise ArchiveRejected(f"{info.filename}: declared size {info.file_size} too large")
        declared_total += info.file_size
    if declared_total > limits.max_total_bytes:
        raise ArchiveRejected(f"declared total {declared_total} too large")


def check_ratio(info: zipfile.ZipInfo, inflated_bytes: int, limits: ExtractionLimits) -> None:
    """Reject an entry whose output so far is far larger than its compressed input."""
    if inflated_bytes < limits.ratio_check_min_bytes:
        return
    # max(..., 1) avoids dividing by zero for a forged compress_size of 0.
    ratio = inflated_bytes / max(info.compress_size, 1)
    if ratio > limits.max_ratio:
        raise ArchiveRejected(f"{info.filename}: compression ratio {ratio:.0f}:1 too high")


def stream_entry(archive: zipfile.ZipFile, info: zipfile.ZipInfo,
                 limits: ExtractionLimits, total_so_far: int) -> bytes:
    """Inflate one entry chunk by chunk, stopping as soon as any limit is crossed."""
    chunks = []
    entry_bytes = 0
    with archive.open(info) as entry:
        while True:
            chunk = entry.read(CHUNK_BYTES)
            if not chunk:
                break
            entry_bytes += len(chunk)
            if entry_bytes > limits.max_entry_bytes:
                raise ArchiveRejected(f"{info.filename}: larger than {limits.max_entry_bytes} bytes")
            if total_so_far + entry_bytes > limits.max_total_bytes:
                raise ArchiveRejected(f"archive larger than {limits.max_total_bytes} bytes")
            check_ratio(info, entry_bytes, limits)
            chunks.append(chunk)
    return b"".join(chunks)


def safe_extract(archive_bytes: bytes, limits: ExtractionLimits = ExtractionLimits()
                 ) -> dict[str, bytes]:
    """Extract regular files from an uploaded ZIP, refusing bombs.

    Nested archives are returned as plain bytes and never extracted
    recursively, so a ZIP inside a ZIP cannot multiply the output.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as error:
        raise ArchiveRejected("not a valid ZIP file") from error
    with archive:
        entries = [info for info in archive.infolist() if not info.is_dir()]
        check_declared_sizes(entries, limits)
        files = {}
        total_bytes = 0
        for info in entries:
            try:
                data = stream_entry(archive, info, limits, total_bytes)
            except zipfile.BadZipFile as error:
                # zipfile raises this on a CRC or size mismatch, e.g. a forged header.
                raise ArchiveRejected(f"{info.filename}: corrupt entry") from error
            total_bytes += len(data)
            files[info.filename] = data
    return files
