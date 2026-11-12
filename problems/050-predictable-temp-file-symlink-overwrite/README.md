# 050 · The billing service's config file was replaced by a CSV of invoices overnight

## Problem
A finance team runs an on-prem reporting host shared by about 40 analysts,
each with their own shell account. A nightly export job runs as the
privileged `billing` service account and writes each customer's invoice
report to the shared scratch directory before uploading it:

```python
path = f"{SCRATCH}/report-{user_id}.csv"
with open(path, "w") as report: ...
```

`SCRATCH` is a group-writable directory all analysts share. One morning the
billing service would not start: its config file contained invoice rows.
The investigation found a symlink `report-1042.csv -> /etc/billing/service.conf`
created by an analyst account the evening before. The same account had also
pre-created `report-2210.csv` as a normal file it owned and could read, so a
second customer's invoices had been written straight into a file the analyst
controlled.

## Root cause
- **The file name was predictable.** Anyone could compute
  `report-<user id>.csv` and create that path before the job ran.
- **`open(path, "w")` trusts whatever is already there.** It follows a
  symlink and truncates the target, using the *service's* permissions, and
  it happily reuses an existing file owned by someone else (same inode, same
  owner, same permissions, so the owner can read the new contents).
- `tempfile.mktemp()` has the same flaw in a different form: it returns an
  unused random name but does not create the file, so another user can
  create it in the gap. Python's docs mark it deprecated for this reason.
- Modern Linux reduces the risk in sticky, world-writable directories such as
  `/tmp` (`fs.protected_symlinks`, and `fs.protected_regular` where enabled),
  but those protections do not cover a group-writable non-sticky directory
  like this one, and other systems do not have them. The code must be safe
  on its own.

## Solution
`export_report` in `solution.py`:

1. **`create_private_dir`** calls `tempfile.mkdtemp`, which creates a
   randomly named directory atomically with mode `0o700`. Other users cannot
   list it or create anything inside, so there is nothing to plant.
2. **`write_report`** calls `tempfile.mkstemp` in that directory. It opens
   with `O_CREAT | O_EXCL`, so it only ever creates a brand-new file (mode
   `0o600`) and never follows a symlink or reuses an existing file. The
   returned descriptor is written through `os.fdopen`; the path is never
   reopened by name.
3. The directory is removed in a `finally` block, even when writing fails.
4. **`open_new_file_no_follow`** is for when a fixed name is unavoidable:
   `os.open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)`. With
   `O_EXCL` the create fails if the path exists at all, including as a
   dangling symlink (`FileExistsError`); `O_NOFOLLOW` is a second guard.

The tests use a temporary directory as the "shared tmp", create real symlinks
with `os.symlink` (skipped where symlinks are unsupported), and show the
original code overwriting the victim file, creating a file through a dangling
symlink and writing into the attacker's own file, while the fixed code leaves
all three untouched.

## Trade-offs
- `O_NOFOLLOW` only checks the *last* path component. A symlinked parent
  directory is still followed, which is why the private `0o700` directory
  matters more than the flags.
- If something must later reopen the file by name (another process, a CLI
  tool), keep it inside the private directory; anywhere shared, the race
  comes back.
- `NamedTemporaryFile(dir=private_dir)` or `TemporaryDirectory()` give the
  same guarantees with automatic cleanup; this example uses the lower-level
  calls to show what they do.
- The best option is often not to use a shared directory at all: give each
  service its own (systemd `PrivateTmp=yes`, a per-user `XDG_RUNTIME_DIR`, or
  a container with its own `/tmp`), or stream the report straight to the
  upload without a temp file.
- Running the export with fewer privileges limits what a missed case can
  overwrite. Related but different problems: path traversal in downloads
  (010) and zip slip on extraction (045).

## Run
```bash
python -m unittest -v test_solution.py
```
