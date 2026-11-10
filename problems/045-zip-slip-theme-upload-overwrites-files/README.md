# 045 · A customer's uploaded theme ZIP overwrote the site builder's own config file

## Problem
A hosted site builder let customers upload a theme as a ZIP file. A worker
extracted each member to `themes/<customer>/` by joining the member name onto
that folder and writing the bytes. A security researcher uploaded a theme that
contained a member named `../../app/config.py` with `DEBUG = True` inside. The
worker wrote it straight over the application's config, and after the next
restart every error page showed stack traces and settings to the public. The
same trick could have dropped a file into a cron folder or replaced a Python
module, which is remote code execution on the theme workers shared by all
customers.

## Root cause
- **Member names inside an archive are attacker-controlled input** but were
  used as file paths unchanged ("zip slip"). `os.path.join(folder, name)`
  happily produces a path outside `folder` when `name` contains `..`
  segments, and returns `name` itself when it is absolute:
  `os.path.join("themes/acme", "/tmp/evil.sh")` is `/tmp/evil.sh`.
- Nothing checked where a member would *finally* land before writing it, and
  archives were written member by member, so a bad member found late left a
  half-extracted theme behind.

## Solution
`safe_extract` in `solution.py`:

1. **Plan before writing.** Every member is validated first; if any one is
   unsafe the whole archive is refused with `UnsafeArchive` and nothing is
   written.
2. **Reject names that are absolute anywhere**: leading `/` or `\`, a drive
   letter (`C:evil.bat`), backslashes (separators on Windows) and NUL bytes.
3. **Compare resolved paths, not strings.** The destination is
   `(root / name).resolve()` and must be the root or have the root among its
   `parents`. A string prefix check would wrongly accept `themes/acme-evil/`
   for the root `themes/acme`; there is a test for that. `css/../index.html`
   still extracts, because it stays inside.
4. **Refuse symlink members.** A link pointing outside the folder would let a
   later member be written *through* it.
5. **Cap the member count** (2,000) so one upload cannot create millions of
   files. Size limits for decompression bombs are covered in problem 019.

## Trade-offs
- Python's own `ZipFile.extract()` / `extractall()` already strip `..` and
  absolute prefixes; the bug appears whenever code writes members itself (to
  rename, filter or stream to object storage), which is common. For tar files
  on Python 3.12+, `tarfile.extractall(filter="data")` does similar checks.
- The check resolves paths on the local filesystem. If another process can
  create symlinks inside the target folder between the check and the write,
  extract into a fresh private temporary folder and move it into place.
- Refusing the whole archive is strict: one odd file name blocks the upload.
  That is deliberate for untrusted uploads; the error names the bad member so
  the customer can fix it.

## Run
```bash
python -m unittest -v test_solution.py
```
