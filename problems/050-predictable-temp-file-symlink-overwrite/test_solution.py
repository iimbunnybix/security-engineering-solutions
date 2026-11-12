import os
import stat
import tempfile
import unittest
from pathlib import Path

from solution import (PRIVATE_FILE_MODE, create_private_dir, export_report, naive_write_report,
                      open_new_file_no_follow, predictable_report_path, write_report)

USER_ID = 1042
VICTIM_CONTENT = "db_password_file=/run/secrets/db\n"
REPORT_ROWS = [("invoice", "amount"), ("INV-1", "120.00"), ("INV-2", "75.50")]
EXPECTED_CSV = "invoice,amount\r\nINV-1,120.00\r\nINV-2,75.50\r\n"
IS_POSIX = os.name == "posix"


def symlinks_supported() -> bool:
    """Windows without developer mode cannot create symlinks; skip those tests there."""
    with tempfile.TemporaryDirectory() as scratch:
        try:
            os.symlink(Path(scratch) / "target", Path(scratch) / "link")
        except (OSError, NotImplementedError):
            return False
    return True


SYMLINKS = symlinks_supported()


class SharedTmpTestCase(unittest.TestCase):
    """Gives each test a fake shared /tmp and a protected file outside it."""

    def setUp(self) -> None:
        workspace = tempfile.TemporaryDirectory()
        self.addCleanup(workspace.cleanup)
        root = Path(workspace.name)
        self.shared_tmp = root / "tmp"
        self.shared_tmp.mkdir()
        protected_dir = root / "etc"
        protected_dir.mkdir()
        self.victim = protected_dir / "service.conf"
        self.victim.write_text(VICTIM_CONTENT)

    def plant_symlink_to_victim(self) -> Path:
        """What the attacker does: point the predictable name at the victim file."""
        link = predictable_report_path(self.shared_tmp, USER_ID)
        os.symlink(self.victim, link)
        return link

    def plant_attacker_file(self) -> Path:
        """The leak variant: the attacker creates the file first and keeps it."""
        planted = predictable_report_path(self.shared_tmp, USER_ID)
        planted.write_text("")
        return planted


@unittest.skipUnless(SYMLINKS, "symlinks are not supported here")
class ReproduceProblem(SharedTmpTestCase):
    def test_planted_symlink_makes_the_service_overwrite_the_victim_file(self):
        self.plant_symlink_to_victim()
        naive_write_report(self.shared_tmp, USER_ID, REPORT_ROWS)
        self.assertEqual(self.victim.read_bytes().decode(), EXPECTED_CSV)

    def test_dangling_symlink_makes_the_service_create_a_file_elsewhere(self):
        self.victim.unlink()
        self.plant_symlink_to_victim()
        naive_write_report(self.shared_tmp, USER_ID, REPORT_ROWS)
        self.assertTrue(self.victim.exists())

    def test_report_is_written_into_a_file_the_attacker_created(self):
        planted = self.plant_attacker_file()
        inode_before = planted.stat().st_ino
        naive_write_report(self.shared_tmp, USER_ID, REPORT_ROWS)
        self.assertEqual(planted.stat().st_ino, inode_before)
        self.assertEqual(planted.read_bytes().decode(), EXPECTED_CSV)


@unittest.skipUnless(SYMLINKS, "symlinks are not supported here")
class FixRefusesPlantedPaths(SharedTmpTestCase):
    def test_export_leaves_the_victim_file_untouched(self):
        self.plant_symlink_to_victim()
        export_report(self.shared_tmp, USER_ID, REPORT_ROWS)
        self.assertEqual(self.victim.read_text(), VICTIM_CONTENT)

    def test_export_does_not_write_into_the_attacker_file(self):
        planted = self.plant_attacker_file()
        export_report(self.shared_tmp, USER_ID, REPORT_ROWS)
        self.assertEqual(planted.read_text(), "")

    def test_exclusive_open_refuses_a_symlink(self):
        link = self.plant_symlink_to_victim()
        with self.assertRaises(OSError):
            open_new_file_no_follow(link)
        self.assertEqual(self.victim.read_text(), VICTIM_CONTENT)

    def test_exclusive_open_refuses_a_dangling_symlink(self):
        self.victim.unlink()
        link = self.plant_symlink_to_victim()
        with self.assertRaises(OSError):
            open_new_file_no_follow(link)
        self.assertFalse(self.victim.exists())

    def test_exclusive_open_refuses_an_existing_file(self):
        planted = self.plant_attacker_file()
        with self.assertRaises(FileExistsError):
            open_new_file_no_follow(planted)


class FixWritesPrivately(SharedTmpTestCase):
    def test_export_returns_the_report_contents(self):
        self.assertEqual(export_report(self.shared_tmp, USER_ID, REPORT_ROWS), EXPECTED_CSV)

    def test_export_cleans_up_its_private_directory(self):
        export_report(self.shared_tmp, USER_ID, REPORT_ROWS)
        self.assertEqual(list(self.shared_tmp.iterdir()), [])

    def test_two_reports_for_the_same_user_get_different_files(self):
        private_dir = create_private_dir(self.shared_tmp)
        first = write_report(private_dir, USER_ID, REPORT_ROWS)
        second = write_report(private_dir, USER_ID, REPORT_ROWS)
        self.assertNotEqual(first, second)

    def test_exclusive_open_creates_a_new_file(self):
        path = self.shared_tmp / "fixed-name.csv"
        os.close(open_new_file_no_follow(path))
        self.assertTrue(path.is_file())

    @unittest.skipUnless(IS_POSIX, "POSIX permission bits")
    def test_private_directory_is_only_accessible_by_its_owner(self):
        private_dir = create_private_dir(self.shared_tmp)
        self.assertEqual(stat.S_IMODE(private_dir.stat().st_mode), 0o700)

    @unittest.skipUnless(IS_POSIX, "POSIX permission bits")
    def test_report_file_is_only_readable_by_its_owner(self):
        path = write_report(create_private_dir(self.shared_tmp), USER_ID, REPORT_ROWS)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), PRIVATE_FILE_MODE)


if __name__ == "__main__":
    unittest.main()
