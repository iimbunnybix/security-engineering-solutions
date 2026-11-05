import io
import random
import struct
import unittest
import zipfile

from solution import (
    MIB,
    ArchiveRejected,
    ExtractionLimits,
    naive_extract,
    safe_extract,
)

BOMB_ENTRY_BYTES = 16 * MIB
BOMB_ENTRY_COUNT = 4
CENTRAL_HEADER_SIGNATURE = b"PK\x01\x02"
LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
CENTRAL_SIZE_OFFSET = 24     # uncompressed size field in a central directory record
LOCAL_SIZE_OFFSET = 22       # uncompressed size field in a local file header


def build_zip(files: dict[str, bytes]) -> bytes:
    """Build a deflate-compressed ZIP in memory."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def build_bomb() -> bytes:
    """A few entries of zeros: tiny on the wire, 64 MiB once inflated."""
    files = {}
    for index in range(BOMB_ENTRY_COUNT):
        files[f"data{index}.csv"] = bytes(BOMB_ENTRY_BYTES)
    return build_zip(files)


def forge_declared_size(archive_bytes: bytes, fake_size: int) -> bytes:
    """Overwrite the uncompressed-size fields so the headers lie about the size."""
    data = bytearray(archive_bytes)
    for signature, offset in ((CENTRAL_HEADER_SIGNATURE, CENTRAL_SIZE_OFFSET),
                              (LOCAL_HEADER_SIGNATURE, LOCAL_SIZE_OFFSET)):
        position = data.find(signature)
        struct.pack_into("<I", data, position + offset, fake_size)
    return bytes(data)


def normal_upload() -> dict[str, bytes]:
    """What a real customer uploads: a CSV and a small image-like binary."""
    rows = "".join(f"{index},sku-{index},{index * 7 % 100}\n" for index in range(20000))
    # Real images are already compressed, so seeded random bytes stand in for one.
    pseudo_image = random.Random(19).randbytes(200000)
    return {"products.csv": rows.encode(), "logo.png": pseudo_image}


class ReproduceProblem(unittest.TestCase):
    def test_small_upload_inflates_to_far_more_memory(self):
        bomb = build_bomb()
        files = naive_extract(bomb)
        inflated = sum(len(data) for data in files.values())
        self.assertEqual(inflated, BOMB_ENTRY_COUNT * BOMB_ENTRY_BYTES)
        self.assertGreater(inflated / len(bomb), 900)


class FixRejectsBombs(unittest.TestCase):
    def test_bomb_is_rejected(self):
        with self.assertRaises(ArchiveRejected):
            safe_extract(build_bomb())

    def test_entry_with_honest_large_size_is_rejected_before_inflating(self):
        limits = ExtractionLimits(max_entry_bytes=1 * MIB)
        archive = build_zip({"big.bin": bytes(2 * MIB)})
        with self.assertRaisesRegex(ArchiveRejected, "declared size"):
            safe_extract(archive, limits)

    def test_forged_small_declared_size_is_still_rejected(self):
        archive = forge_declared_size(build_zip({"big.bin": bytes(BOMB_ENTRY_BYTES)}), 100)
        with self.assertRaises(ArchiveRejected):
            safe_extract(archive)

    def test_many_entries_under_each_limit_hit_the_total_limit(self):
        limits = ExtractionLimits(max_entry_bytes=1 * MIB, max_total_bytes=3 * MIB, max_ratio=10**6)
        files = {f"part{index}.txt": bytes(MIB) for index in range(5)}
        with self.assertRaisesRegex(ArchiveRejected, "total"):
            safe_extract(build_zip(files), limits)

    def test_too_many_entries_is_rejected(self):
        files = {f"f{index}.txt": b"x" for index in range(11)}
        with self.assertRaisesRegex(ArchiveRejected, "too many entries"):
            safe_extract(build_zip(files), ExtractionLimits(max_entries=10))

    def test_high_ratio_entry_under_size_limits_is_rejected(self):
        archive = build_zip({"zeros.bin": bytes(5 * MIB)})
        with self.assertRaisesRegex(ArchiveRejected, "compression ratio"):
            safe_extract(archive)

    def test_garbage_upload_is_rejected_cleanly(self):
        with self.assertRaisesRegex(ArchiveRejected, "not a valid ZIP"):
            safe_extract(b"this is not a zip file")


class FixAcceptsNormalUploads(unittest.TestCase):
    def test_normal_upload_extracts_unchanged(self):
        files = normal_upload()
        self.assertEqual(safe_extract(build_zip(files)), files)

    def test_small_repetitive_file_is_allowed_despite_high_ratio(self):
        files = {"blank.txt": b"\n" * 100000}
        self.assertEqual(safe_extract(build_zip(files)), files)

    def test_nested_zip_is_returned_as_bytes_not_extracted(self):
        inner = build_zip({"zeros.bin": bytes(MIB)})
        result = safe_extract(build_zip({"inner.zip": inner}))
        self.assertEqual(result, {"inner.zip": inner})

    def test_directories_are_skipped(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("docs/", b"")
            archive.writestr("docs/readme.txt", b"hello")
        self.assertEqual(safe_extract(buffer.getvalue()), {"docs/readme.txt": b"hello"})


if __name__ == "__main__":
    unittest.main()
