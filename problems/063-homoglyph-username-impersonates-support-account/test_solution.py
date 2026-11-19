import unittest

from solution import UsernameRegistry, UsernameRejected, naive_is_available, skeleton

CYRILLIC_O = chr(0x043E)
CYRILLIC_A = chr(0x0430)
CYRILLIC_DZE = chr(0x0455)       # looks like "s"
ZERO_WIDTH_SPACE = chr(0x200B)

FAKE_SUPPORT_NAMES = [
    "supp" + CYRILLIC_O + "rt",
    CYRILLIC_DZE + "upport",
    "sup" + ZERO_WIDTH_SPACE + "port",
]


def registry_with(*usernames):
    registry = UsernameRegistry()
    for username in usernames:
        registry.register(username)
    return registry


class ReproduceProblem(unittest.TestCase):
    def test_look_alike_support_names_pass_the_naive_check(self):
        for fake_name in FAKE_SUPPORT_NAMES:
            with self.subTest(fake_name=fake_name):
                self.assertTrue(naive_is_available(fake_name, existing=set()))

    def test_look_alike_of_existing_user_passes_the_naive_check(self):
        self.assertTrue(naive_is_available("r" + CYRILLIC_A + "hul", existing={"rahul"}))

    def test_exact_reserved_name_was_already_blocked(self):
        self.assertFalse(naive_is_available("Support", existing=set()))


class FixReservedLookAlikes(unittest.TestCase):
    def test_single_script_look_alike_of_reserved_name_is_rejected(self):
        with self.assertRaises(UsernameRejected):
            UsernameRegistry().check("supp0rt")

    def test_full_width_letters_are_rejected(self):
        with self.assertRaises(UsernameRejected):
            UsernameRegistry().check("ｓｕｐｐｏｒｔ")

    def test_mixed_script_names_are_rejected(self):
        for fake_name in FAKE_SUPPORT_NAMES[:2]:
            with self.subTest(fake_name=fake_name):
                with self.assertRaisesRegex(UsernameRejected, "different alphabets"):
                    UsernameRegistry().check(fake_name)

    def test_invisible_character_is_rejected(self):
        with self.assertRaisesRegex(UsernameRejected, "invisible"):
            UsernameRegistry().check(FAKE_SUPPORT_NAMES[2])

    def test_all_cyrillic_look_alike_of_reserved_name_is_rejected(self):
        all_cyrillic_help = chr(0x04BB) + chr(0x0435) + chr(0x04CF) + chr(0x0440)
        with self.assertRaisesRegex(UsernameRejected, "reserved"):
            UsernameRegistry().check(all_cyrillic_help)

    def test_skeleton_maps_look_alikes_to_latin(self):
        self.assertEqual(skeleton(CYRILLIC_A + chr(0x0501) + "M" + chr(0x0456) + "n"), "admin")


class FixExistingUserLookAlikes(unittest.TestCase):
    def test_digit_one_for_letter_l_collides_with_existing_user(self):
        registry = registry_with("rahul")
        with self.assertRaisesRegex(UsernameRejected, "rahul"):
            registry.check("rahu1")

    def test_different_case_collides_with_existing_user(self):
        registry = registry_with("priya")
        with self.assertRaises(UsernameRejected):
            registry.check("Priya")


class FixLegitimateNames(unittest.TestCase):
    def test_ordinary_name_is_accepted(self):
        registry_with("rahul", "priya_88")

    def test_name_in_one_non_latin_script_is_accepted(self):
        registry_with("иван")

    def test_accented_latin_name_is_accepted(self):
        registry_with("josé.m")


if __name__ == "__main__":
    unittest.main()
