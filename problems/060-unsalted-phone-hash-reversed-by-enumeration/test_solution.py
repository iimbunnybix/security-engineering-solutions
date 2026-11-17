import unittest

from solution import (dictionary_attack, enumerate_block, keyed_pseudonym,
                      naive_pseudonym, new_partner_key, normalise_phone)

# The attack in the tests covers one 100,000-number block; the real space of
# Indian mobiles is 4 billion numbers, which is hours of work on one GPU.
BLOCK_PREFIX = "98200"
CUSTOMERS = ["+91 98200 12345", "98200-55501", "09820099999"]


def candidate_block() -> list[str]:
    return list(enumerate_block(BLOCK_PREFIX, 5))


class ReproduceProblem(unittest.TestCase):
    def test_every_customer_phone_is_recovered_from_the_export(self):
        export = {naive_pseudonym(phone) for phone in CUSTOMERS}
        recovered = dictionary_attack(export, candidate_block(), naive_pseudonym)
        self.assertEqual(sorted(recovered.values()), ["9820012345", "9820055501", "9820099999"])

    def test_two_partners_can_join_their_exports_on_the_hash(self):
        self.assertEqual(naive_pseudonym(CUSTOMERS[0]), naive_pseudonym("9820012345"))


class FixKeyedPseudonyms(unittest.TestCase):
    def test_enumeration_without_the_key_recovers_nothing(self):
        partner_key = new_partner_key()
        export = {keyed_pseudonym(phone, partner_key) for phone in CUSTOMERS}
        recovered = dictionary_attack(export, candidate_block(), naive_pseudonym)
        self.assertEqual(recovered, {})

    def test_attacker_with_a_guessed_key_recovers_nothing(self):
        partner_key = new_partner_key()
        wrong_key = new_partner_key()
        export = {keyed_pseudonym(phone, partner_key) for phone in CUSTOMERS}
        recovered = dictionary_attack(export, candidate_block(),
                                      lambda phone: keyed_pseudonym(phone, wrong_key))
        self.assertEqual(recovered, {})

    def test_same_phone_gets_the_same_token_for_one_partner(self):
        partner_key = new_partner_key()
        self.assertEqual(keyed_pseudonym("+91 98200 12345", partner_key),
                         keyed_pseudonym("9820012345", partner_key))

    def test_two_partners_get_unlinkable_tokens(self):
        first_partner, second_partner = new_partner_key(), new_partner_key()
        self.assertNotEqual(keyed_pseudonym(CUSTOMERS[0], first_partner),
                            keyed_pseudonym(CUSTOMERS[0], second_partner))

    def test_short_key_is_rejected(self):
        with self.assertRaises(ValueError):
            keyed_pseudonym(CUSTOMERS[0], b"short")


class PhoneNormalisation(unittest.TestCase):
    def test_country_code_trunk_zero_and_spacing_are_removed(self):
        for raw in ("+91 98200 12345", "919820012345", "09820012345", "(98200) 12-345"):
            with self.subTest(raw=raw):
                self.assertEqual(normalise_phone(raw), "9820012345")

    def test_landline_style_number_is_rejected(self):
        with self.assertRaises(ValueError):
            normalise_phone("2212345678")

    def test_letters_and_non_ascii_digits_are_rejected(self):
        for raw in ("98200 1234x", "९८२००१२३४५"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                normalise_phone(raw)


if __name__ == "__main__":
    unittest.main()
