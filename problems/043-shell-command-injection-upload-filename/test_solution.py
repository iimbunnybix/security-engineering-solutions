import tempfile
import unittest
from pathlib import Path

from solution import (LineCountError, UnsafeFilenameError, build_line_count_argv,
                      naive_count_lines, parse_line_count, safe_count_lines)

MARKER = "INJECTED"
CSV_ROWS = "id,amount\n1,10\n2,20\n"
CSV_LINE_COUNT = 3


class UploadDirFixture(unittest.TestCase):
    """A fresh, empty upload directory for every test."""

    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        self.upload_dir = Path(self._temp.name)

    def tearDown(self):
        self._temp.cleanup()

    def upload(self, filename: str, content: str = CSV_ROWS) -> None:
        """Store a file under the customer's original name, as the app did."""
        (self.upload_dir / filename).write_text(content)

    def marker_was_created(self) -> bool:
        """The attacker's command touches MARKER; its existence proves execution."""
        return (self.upload_dir / MARKER).exists()


INJECTION_FILENAMES = [
    f"orders.csv; touch {MARKER}",
    f"$(touch {MARKER}).csv",
    f"`touch {MARKER}`.csv",
    f"orders.csv | touch {MARKER}",
    f"orders.csv || touch {MARKER}",
]


class ReproduceProblem(UploadDirFixture):
    def test_semicolon_in_filename_runs_a_second_command(self):
        naive_count_lines(self.upload_dir, f"orders.csv; touch {MARKER}")
        self.assertTrue(self.marker_was_created())

    def test_every_common_shell_metacharacter_runs_the_command(self):
        for filename in INJECTION_FILENAMES:
            with self.subTest(filename=filename):
                (self.upload_dir / MARKER).unlink(missing_ok=True)
                naive_count_lines(self.upload_dir, filename)
                self.assertTrue(self.marker_was_created())

    def test_filename_with_a_space_is_counted_wrongly(self):
        self.upload("q3 report.csv")
        output = naive_count_lines(self.upload_dir, "q3 report.csv")
        self.assertNotIn(f"{CSV_LINE_COUNT} q3 report.csv", output)

    def test_filename_starting_with_dash_is_read_as_an_option(self):
        self.upload("--version")
        output = naive_count_lines(self.upload_dir, "--version")
        self.assertFalse(output.startswith(str(CSV_LINE_COUNT)))


class FixArgumentListWithoutShell(UploadDirFixture):
    def test_plain_filename_is_counted(self):
        self.upload("orders.csv")
        self.assertEqual(safe_count_lines(self.upload_dir, "orders.csv"), CSV_LINE_COUNT)

    def test_injection_filenames_run_nothing(self):
        for filename in INJECTION_FILENAMES:
            with self.subTest(filename=filename):
                with self.assertRaises(LineCountError):
                    safe_count_lines(self.upload_dir, filename)
                self.assertFalse(self.marker_was_created())

    def test_real_file_with_shell_characters_in_its_name_is_counted(self):
        filename = f"orders.csv; touch {MARKER}"
        self.upload(filename)
        self.assertEqual(safe_count_lines(self.upload_dir, filename), CSV_LINE_COUNT)
        self.assertFalse(self.marker_was_created())

    def test_filename_with_spaces_and_quotes_is_counted(self):
        filename = "Q3 'final' \"v2\".csv"
        self.upload(filename)
        self.assertEqual(safe_count_lines(self.upload_dir, filename), CSV_LINE_COUNT)

    def test_filename_starting_with_dash_is_read_as_a_file(self):
        self.upload("--version")
        self.assertEqual(safe_count_lines(self.upload_dir, "--version"), CSV_LINE_COUNT)

    def test_argv_passes_the_filename_as_one_argument_after_end_of_options(self):
        filename = f"a b; touch {MARKER}"
        self.assertEqual(build_line_count_argv(filename), ["wc", "-l", "--", filename])

    def test_names_that_leave_the_upload_directory_are_refused(self):
        for filename in ["../secrets.csv", "sub/orders.csv", "..\\orders.csv",
                         "..", ".", "", "a\0b.csv"]:
            with self.subTest(filename=filename):
                with self.assertRaises(UnsafeFilenameError):
                    safe_count_lines(self.upload_dir, filename)

    def test_overlong_filename_is_refused(self):
        with self.assertRaises(UnsafeFilenameError):
            safe_count_lines(self.upload_dir, "a" * 256)

    def test_missing_file_raises_instead_of_returning_a_count(self):
        with self.assertRaises(LineCountError):
            safe_count_lines(self.upload_dir, "missing.csv")

    def test_empty_file_has_zero_lines(self):
        self.upload("empty.csv", content="")
        self.assertEqual(safe_count_lines(self.upload_dir, "empty.csv"), 0)

    def test_unparseable_output_raises(self):
        with self.assertRaises(LineCountError):
            parse_line_count("wc: something went wrong")


if __name__ == "__main__":
    unittest.main()
