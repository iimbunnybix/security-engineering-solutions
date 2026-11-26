# 076 · An attacker ran code on the support portal by uploading "shell.PHP" past the upload filter

## Problem
A support portal lets customers attach scanned documents and photos to a
ticket. Uploads were saved under the customer's file name in an `uploads/`
folder served by the same PHP-enabled web server. To stop scripts, the
upload handler rejected names ending in `.php`, `.exe`, `.sh`, `.html` or
`.js`.

During a penetration test, the tester uploaded `shell.PHP`, opened
`/uploads/shell.PHP` and got a command prompt on the server. Later tries
showed that `shell.php5`, `shell.phtml` and, on the Windows staging box,
`shell.php.` and `shell.php::$DATA` worked too. The portal had access to
every customer's tickets and attachments.

## Root cause
**A denylist of spellings, checked differently from how the server
interprets them.** `endswith(".php")` is case-sensitive, but the web server
maps extensions case-insensitively on many setups. PHP handlers are often
also mapped to `.php5`, `.phtml` and `.phar`. Windows strips trailing dots
and spaces (`shell.php.` is saved as `shell.php`), and `::$DATA` names the
file's main NTFS stream. All seven bypass names in the tests pass the
original check. Storing the file under the client's own name then let the
attacker choose and know its URL.

This differs from SVG stored XSS (problem 034, an allowed type with
dangerous content) and zip slip (problem 045, path traversal inside an
archive). Here the file type check itself was bypassed.

## Solution
1. **Allowlist.** Only `pdf`, `png`, `jpg` and `jpeg` are accepted, compared
   case-insensitively on the text after the last dot. Anything not listed is
   refused, including types nobody had thought of.
2. **Refuse ambiguous names** instead of normalising them: NUL, `:`,
   slashes and backslashes, trailing dots or spaces, names with no
   extension (`.htaccess`), and names over 255 characters. Different
   systems disagree on what these mean, so we do not guess.
3. **Server-chosen name.** The file is stored as 32 random hex characters
   plus the *canonical* extension (`photo.Jpeg` becomes `<random>.jpg`).
   The client's spelling is kept only as metadata for display. So
   `invoice.php.pdf` is stored as `<random>.pdf`. That matters because
   Apache's `AddHandler` can run a file as PHP if *any* of its extensions is
   `.php`.

## Trade-offs
- **The extension is still a claim.** A `.png` can contain HTML or a PHP
  payload. Check the file's magic bytes, and re-encode images if you can.
  Most importantly, serve uploads from a separate domain or storage bucket
  with no script execution and `Content-Disposition: attachment`
  (problem 034 has the content-type side).
- **Allowlists need maintenance.** When product wants `.heic` photos, someone
  has to add it, which is the point: adding a type becomes a decision.
- **Rejecting odd names annoys some users** whose files end in a space or
  contain `:`. The error message tells them to rename, which is rare and
  cheap compared to the alternative.

## Run
```bash
python -m unittest -v test_solution.py
```
