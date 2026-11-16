import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from solution import UnsafeArchive, naive_restore, safe_restore


def build_tar(entries: list[tuple[str, str, str]]) -> io.BytesIO:
    """Build an in-memory tar from (kind, name, payload) entries.

    kind is "file" (payload = text), "dir", "symlink" or "hardlink"
    (payload = link target).
    """
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for kind, name, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = payload.encode()
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
                continue
            if kind == "dir":
                info.type = tarfile.DIRTYPE
            elif kind == "symlink":
                info.type, info.linkname = tarfile.SYMTYPE, payload
            elif kind == "hardlink":
                info.type, info.linkname = tarfile.LNKTYPE, payload
            archive.addfile(info)
    buffer.seek(0)
    return buffer


class TempFolders(unittest.TestCase):
    """Gives each test a fresh workspace and a separate 'app' folder."""

    def setUp(self) -> None:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.workspace = Path(temp.name) / "workspace"
        self.app_folder = Path(temp.name) / "app"
        self.workspace.mkdir()
        self.app_folder.mkdir()
        self.server_secret = self.app_folder / "settings.py"
        self.server_secret.write_text("DATABASE_PASSWORD = 'not-a-real-one'\n")

    def symlink_then_write_archive(self) -> io.BytesIO:
        return build_tar([
            ("symlink", "uploads", str(self.app_folder)),
            ("file", "uploads/settings.py", "DEBUG = True  # attacker controlled\n"),
        ])

    def hardlink_archive(self) -> io.BytesIO:
        return build_tar([("hardlink", "notes.txt", str(self.server_secret))])


class ReproduceProblem(TempFolders):
    def test_member_names_alone_look_safe(self):
        names = [member.name for member in tarfile.open(fileobj=self.symlink_then_write_archive())]
        self.assertEqual(names, ["uploads", "uploads/settings.py"])

    def test_file_written_through_symlink_overwrites_app_settings(self):
        naive_restore(self.symlink_then_write_archive(), self.workspace)
        self.assertIn("attacker controlled", self.server_secret.read_text())

    def test_hardlink_member_exposes_a_server_file_in_the_workspace(self):
        naive_restore(self.hardlink_archive(), self.workspace)
        self.assertIn("DATABASE_PASSWORD", (self.workspace / "notes.txt").read_text())

    def test_dotdot_names_were_already_refused(self):
        with self.assertRaises(UnsafeArchive):
            naive_restore(build_tar([("file", "../escape.txt", "x")]), self.workspace)


class FixRefusesLinks(TempFolders):
    def test_symlink_member_is_refused_and_app_file_is_unchanged(self):
        with self.assertRaisesRegex(UnsafeArchive, "symlink"):
            safe_restore(self.symlink_then_write_archive(), self.workspace)
        self.assertNotIn("attacker", self.server_secret.read_text())

    def test_nothing_is_written_when_a_later_member_is_bad(self):
        archive = build_tar([("file", "readme.txt", "hi"), ("symlink", "x", "/")])
        with self.assertRaises(UnsafeArchive):
            safe_restore(archive, self.workspace)
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_hardlink_member_is_refused(self):
        with self.assertRaisesRegex(UnsafeArchive, "hardlink"):
            safe_restore(self.hardlink_archive(), self.workspace)

    def test_relative_symlink_inside_the_workspace_is_also_refused(self):
        archive = build_tar([("file", "a.txt", "x"), ("symlink", "b.txt", "a.txt")])
        with self.assertRaises(UnsafeArchive):
            safe_restore(archive, self.workspace)

    def test_existing_symlink_in_destination_is_not_followed(self):
        os.symlink(self.app_folder, self.workspace / "uploads")
        archive = build_tar([("file", "uploads/settings.py", "DEBUG = True\n")])
        with self.assertRaisesRegex(UnsafeArchive, "outside"):
            safe_restore(archive, self.workspace)
        self.assertNotIn("DEBUG", self.server_secret.read_text())

    def test_dotdot_and_absolute_names_are_refused(self):
        for name in ["../escape.txt", "/etc/escape.txt", "docs/../../escape.txt"]:
            with self.subTest(name=name), self.assertRaises(UnsafeArchive):
                safe_restore(build_tar([("file", name, "x")]), self.workspace)


class FixStillRestoresNormalBackups(TempFolders):
    def test_files_and_folders_are_restored(self):
        archive = build_tar([
            ("dir", "docs", ""),
            ("file", "docs/plan.md", "# Plan\n"),
            ("file", "images/logo.txt", "logo"),
        ])
        restored = safe_restore(archive, self.workspace)
        self.assertEqual(restored, ["docs/plan.md", "images/logo.txt"])
        self.assertEqual((self.workspace / "docs/plan.md").read_text(), "# Plan\n")

    def test_restored_files_get_safe_permissions(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            info = tarfile.TarInfo("run.sh")
            info.mode = 0o4777  # setuid and world-writable
            archive.addfile(info, io.BytesIO(b""))
        buffer.seek(0)
        safe_restore(buffer, self.workspace)
        self.assertEqual((self.workspace / "run.sh").stat().st_mode & 0o7777, 0o644)


if __name__ == "__main__":
    unittest.main()
