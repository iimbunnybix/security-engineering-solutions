import io
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from solution import (MAX_MEMBERS, UNIX_MODE_SHIFT, UnsafeArchive,
                      naive_extract, safe_extract)


def build_archive(files: dict[str, bytes]) -> zipfile.ZipFile:
    """Build an in-memory ZIP whose member names we choose freely."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as writer:
        for name, content in files.items():
            writer.writestr(name, content)
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def build_archive_with_symlink(link_name: str, link_target: str) -> zipfile.ZipFile:
    """Build a ZIP containing one Unix symlink member."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as writer:
        info = zipfile.ZipInfo(link_name)
        info.external_attr = (stat.S_IFLNK | 0o777) << UNIX_MODE_SHIFT
        writer.writestr(info, link_target)
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


class WorkspaceTestCase(unittest.TestCase):
    """Gives each test a fresh folder with app/ and themes/acme/ inside."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.app_config = self.root / "app" / "config.py"
        self.app_config.parent.mkdir()
        self.app_config.write_text("DEBUG = False\n")
        self.theme_folder = self.root / "themes" / "acme"

    def tearDown(self):
        self.temp.cleanup()


class ReproduceProblem(WorkspaceTestCase):
    def test_normal_theme_extracts_into_its_folder(self):
        archive = build_archive({"css/site.css": b"body{}"})
        naive_extract(archive, self.theme_folder)
        self.assertEqual((self.theme_folder / "css" / "site.css").read_bytes(), b"body{}")

    def test_dot_dot_member_overwrites_application_code(self):
        archive = build_archive({"../../app/config.py": b"DEBUG = True\n"})
        naive_extract(archive, self.theme_folder)
        self.assertEqual(self.app_config.read_text(), "DEBUG = True\n")


class FixSafeExtract(WorkspaceTestCase):
    def assert_rejected_and_app_untouched(self, archive: zipfile.ZipFile) -> None:
        with self.assertRaises(UnsafeArchive):
            safe_extract(archive, self.theme_folder)
        self.assertEqual(self.app_config.read_text(), "DEBUG = False\n")

    def test_normal_theme_extracts_into_its_folder(self):
        archive = build_archive({"css/site.css": b"body{}", "index.html": b"<p>"})
        written = safe_extract(archive, self.theme_folder)
        self.assertEqual(len(written), 2)
        self.assertEqual((self.theme_folder / "index.html").read_bytes(), b"<p>")

    def test_dot_dot_member_is_rejected(self):
        self.assert_rejected_and_app_untouched(
            build_archive({"../../app/config.py": b"DEBUG = True\n"}))

    def test_dot_dot_hidden_inside_path_is_rejected(self):
        self.assert_rejected_and_app_untouched(
            build_archive({"css/../../../app/config.py": b"x"}))

    def test_dot_dot_that_stays_inside_is_allowed(self):
        archive = build_archive({"css/../index.html": b"<p>"})
        safe_extract(archive, self.theme_folder)
        self.assertTrue((self.theme_folder / "index.html").exists())

    def test_absolute_path_is_rejected(self):
        self.assert_rejected_and_app_untouched(build_archive({"/tmp/evil.sh": b"x"}))

    def test_windows_drive_and_backslash_names_are_rejected(self):
        for name in ["C:evil.bat", "..\\..\\app\\config.py"]:
            with self.subTest(name=name):
                self.assert_rejected_and_app_untouched(build_archive({name: b"x"}))

    def test_sibling_folder_with_same_prefix_is_rejected(self):
        # "themes/acme-evil" starts with the string "themes/acme"; a prefix
        # check on strings would wrongly allow it.
        self.assert_rejected_and_app_untouched(build_archive({"../acme-evil/x.css": b"x"}))

    def test_symlink_member_is_rejected(self):
        self.assert_rejected_and_app_untouched(
            build_archive_with_symlink("link", "../../app"))

    def test_rejected_archive_writes_nothing_at_all(self):
        archive = build_archive({"good.css": b"ok", "../../app/config.py": b"bad"})
        with self.assertRaises(UnsafeArchive):
            safe_extract(archive, self.theme_folder)
        self.assertFalse((self.theme_folder / "good.css").exists())

    def test_archive_with_too_many_members_is_rejected(self):
        files = {f"f{index}.txt": b"" for index in range(MAX_MEMBERS + 1)}
        self.assert_rejected_and_app_untouched(build_archive(files))


if __name__ == "__main__":
    unittest.main()
