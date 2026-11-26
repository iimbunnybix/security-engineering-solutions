import re
import unittest

from solution import RejectedUpload, canonical_extension, naive_is_allowed, store_upload

BYPASS_NAMES = ["shell.PHP", "shell.pHp", "shell.php.", "shell.php ", "shell.php5",
                "shell.phtml", "shell.php::$DATA"]


class ReproduceProblem(unittest.TestCase):
    def test_plain_php_name_is_blocked(self):
        self.assertFalse(naive_is_allowed("shell.php"))

    def test_every_bypass_spelling_passes_the_denylist(self):
        for name in BYPASS_NAMES:
            with self.subTest(name=name):
                self.assertTrue(naive_is_allowed(name))


class FixAllowlist(unittest.TestCase):
    def test_every_bypass_spelling_is_rejected(self):
        for name in BYPASS_NAMES:
            with self.subTest(name=name):
                with self.assertRaises(RejectedUpload):
                    canonical_extension(name)

    def test_allowed_types_are_accepted_in_any_case(self):
        self.assertEqual(canonical_extension("invoice.PDF"), "pdf")
        self.assertEqual(canonical_extension("photo.Jpeg"), "jpg")

    def test_only_the_last_extension_counts(self):
        self.assertEqual(canonical_extension("invoice.php.pdf"), "pdf")

    def test_unknown_types_are_rejected(self):
        for name in ("drawing.svg", "page.html", "archive.zip"):
            with self.subTest(name=name):
                with self.assertRaises(RejectedUpload):
                    canonical_extension(name)

    def test_dotfiles_and_names_without_extension_are_rejected(self):
        for name in (".htaccess", ".pdf", "README", ""):
            with self.subTest(name=name):
                with self.assertRaises(RejectedUpload):
                    canonical_extension(name)

    def test_nul_byte_and_path_separators_are_rejected(self):
        for name in ("shell.php\x00.pdf", "../shell.pdf", "..\\shell.pdf"):
            with self.subTest(name=repr(name)):
                with self.assertRaises(RejectedUpload):
                    canonical_extension(name)

    def test_overlong_name_is_rejected(self):
        with self.assertRaises(RejectedUpload):
            canonical_extension("a" * 300 + ".pdf")


class FixServerChosenName(unittest.TestCase):
    def test_stored_name_is_random_with_canonical_extension(self):
        stored = store_upload("Scan From Phone.JPEG")
        self.assertRegex(stored.stored_name, re.compile(r"^[0-9a-f]{32}\.jpg$"))
        self.assertEqual(stored.original_name, "Scan From Phone.JPEG")

    def test_two_uploads_with_the_same_name_get_different_stored_names(self):
        self.assertNotEqual(store_upload("a.pdf").stored_name, store_upload("a.pdf").stored_name)

    def test_double_extension_is_stored_without_the_php_part(self):
        self.assertNotIn("php", store_upload("invoice.php.pdf").stored_name)


if __name__ == "__main__":
    unittest.main()
