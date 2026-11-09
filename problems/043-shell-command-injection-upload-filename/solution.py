"""Count lines of an uploaded CSV without letting its filename run commands.

The import worker counted rows by running ``wc -l <filename>`` through the
shell, pasting the customer's original upload filename into the command
string. The shell treats ``;``, ``$( )``, backticks and ``|`` in that name as
syntax, so a file called ``orders.csv; <any command>`` ran that command.

The fix never involves a shell: the program and each argument are passed as a
list, so the filename reaches ``wc`` as one argument whatever characters it
contains. ``--`` marks the end of options so a name starting with ``-`` is
read as a file, and names with path separators are refused so the worker
only reads files inside the upload directory.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

LINE_COUNT_PROGRAM = "wc"
LINE_COUNT_FLAG = "-l"
# "--" tells wc (and almost every Unix tool) that everything after it is a
# file name, never an option, even if it starts with "-".
END_OF_OPTIONS = "--"
COMMAND_TIMEOUT_SECONDS = 10
MAX_FILENAME_LENGTH = 255
FORBIDDEN_FILENAME_CHARACTERS = ("/", "\\", "\0")
FORBIDDEN_FILENAMES = ("", ".", "..")


class UnsafeFilenameError(ValueError):
    """The filename cannot safely name a file inside the upload directory."""


class LineCountError(RuntimeError):
    """wc failed or printed something we could not parse."""


def naive_count_lines(upload_dir: Path, filename: str) -> str:
    """ORIGINAL: build a shell command string and run it with shell=True.

    Returns whatever the shell printed. Every shell metacharacter in
    ``filename`` is interpreted, which is the vulnerability.
    """
    command = f"{LINE_COUNT_PROGRAM} {LINE_COUNT_FLAG} {filename}"
    result = subprocess.run(command, shell=True, cwd=upload_dir,
                            capture_output=True, text=True,
                            timeout=COMMAND_TIMEOUT_SECONDS)
    return result.stdout


def validate_filename(filename: str) -> None:
    """Refuse names that would point outside the upload directory.

    Shell characters such as ";" or "$" are NOT refused: without a shell they
    are ordinary characters, and real customers do upload "Q3; final.csv".
    """
    if filename in FORBIDDEN_FILENAMES:
        raise UnsafeFilenameError(f"not a file name: {filename!r}")
    if len(filename) > MAX_FILENAME_LENGTH:
        raise UnsafeFilenameError("file name too long")
    for character in FORBIDDEN_FILENAME_CHARACTERS:
        if character in filename:
            raise UnsafeFilenameError(f"file name contains {character!r}")


def build_line_count_argv(filename: str) -> list[str]:
    """The exact argument list handed to the operating system, no shell."""
    validate_filename(filename)
    return [LINE_COUNT_PROGRAM, LINE_COUNT_FLAG, END_OF_OPTIONS, filename]


def parse_line_count(output: str) -> int:
    """wc prints '<count> <name>'; return the count."""
    first_field = output.strip().split(" ", 1)[0]
    if not first_field.isdigit():
        raise LineCountError(f"unexpected wc output: {output!r}")
    return int(first_field)


def safe_count_lines(upload_dir: Path, filename: str) -> int:
    """FIX: run wc with an argument list (shell=False) and return the count."""
    argv = build_line_count_argv(filename)
    # shell=False is the default; it is spelled out because it is the fix.
    result = subprocess.run(argv, shell=False, cwd=upload_dir,
                            capture_output=True, text=True,
                            timeout=COMMAND_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise LineCountError(result.stderr.strip())
    return parse_line_count(result.stdout)
