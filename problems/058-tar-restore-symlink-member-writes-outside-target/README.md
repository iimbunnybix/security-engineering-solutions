# 058 · Restoring a workspace backup overwrote the app's own settings file and turned on debug mode

## Problem
A document-collaboration SaaS lets workspace owners download a `.tar`
backup of their files and upload it later to restore. After a routine
restore by one tenant, the application started serving full stack traces
and its settings module had changed. The uploaded archive contained only
two members — `uploads` and `uploads/settings.py` — and both names had
passed the "no `..`, no absolute paths" check added after an earlier
zip-slip incident (problem 045). Another tenant's archive held a single
member `notes.txt` that, once restored, showed the server's database
password in the workspace file browser. Any workspace owner could do this,
so it was a full server compromise path.

## Root cause
The restore code validated **member names** but then recreated **link
members** exactly as the archive described them:

- `uploads` was a *symlink* to the application folder. The next member,
  `uploads/settings.py`, is a perfectly relative name, but `open()` follows
  the symlink created a moment earlier, so the write lands outside the
  workspace.
- `notes.txt` was a *hardlink* whose link target was an absolute server
  path. `Path("workspace") / "/srv/app/settings.py"` discards the left side,
  so `os.link` made a second name for the server file inside the
  workspace.

A path that looks safe as text can still resolve somewhere else once the
archive's own links exist on disk; checking names is not enough.

## Solution
`safe_restore`:

1. **Validates every member before writing anything**, so a bad archive
   leaves the destination untouched rather than half-restored.
2. **Allows only regular files and directories.** Symlinks, hardlinks,
   devices and FIFOs are refused. Workspace backups never need them, and
   refusing them removes the whole class of link-chaining tricks
   (including relative links that point inside the workspace and could be
   chained later).
3. **Checks the resolved path** of each target is inside the workspace,
   which also catches a symlink already present in the destination.
4. **Normalises permissions** to `0644` / `0755`, so setuid or
   world-writable bits in the archive are dropped.

Files are copied with `extractfile()` rather than `tarfile.extract`, so
behaviour does not depend on the Python version's default extraction
filter.

## Trade-offs
- Python 3.12+ (and security releases of 3.8–3.11) provide
  `tarfile.extractall(filter="data")`, which rejects links pointing
  outside the destination, absolute names and special files, and strips
  dangerous mode bits; Python 3.14 makes it the default. It still allows
  links that stay inside the destination. Use it where available, but an
  explicit "no links" rule is simpler to reason about for this feature.
- Customers who back up project folders with internal symlinks lose those
  links on restore. If they are needed, store them as metadata and
  recreate them only after all files are written, with targets validated.
- A resolved-path check alone has a time-of-check/time-of-use gap if
  another process can create links in the destination concurrently;
  restoring into a fresh private directory and moving it into place
  avoids that.
- Archive size and member count limits (decompression bombs, see problem
  019) are separate controls and still needed.

## Run
```bash
python -m unittest -v test_solution.py
```
