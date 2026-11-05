# 019 · Bulk-import workers crashed with out-of-memory errors after a customer uploaded a 64 KB ZIP

## Problem
A B2B catalogue tool lets merchants upload a ZIP of product CSVs and images
for bulk import. Workers have 2 GB of memory. One afternoon every import
worker was OOM-killed in turn; the queue retried the same job on the next
worker, so imports stopped for all merchants for about an hour. The job's
input was a ZIP of only 64 KB.

The archive was a **zip bomb**: entries full of the same byte compress at
about 1000:1 with deflate. The test bomb here is 4 entries of 16 MiB of zeros:
**65,638 bytes on the wire, 64 MiB once inflated (about 1022:1)**. Real bombs
use more and larger entries (or nested ZIPs) to reach gigabytes.

## Root cause
`naive_extract` trusted the archive: it called `archive.read()` on every
entry, which inflates the whole entry into memory, with no limit on entry
count, entry size, total size or compression ratio. The size of the upload
(which the web tier did limit) says nothing about the size of its contents.

## Solution
`safe_extract` treats the archive as hostile input and enforces limits at two
points:

1. **Before inflating** (`check_declared_sizes`): reject too many entries, an
   entry whose declared size is above the per-entry limit (10 MiB by default)
   or a declared total above the archive limit (50 MiB). This is free and
   catches honest-but-huge archives immediately.
2. **While inflating** (`stream_entry`): read each entry in 64 KiB chunks and
   count the real bytes, stopping as soon as the entry or the running total
   crosses its limit, or the entry's output/compressed ratio exceeds 100:1
   once it has produced 1 MiB. Normal content stays far below that ratio (the
   test CSV compresses about 3.6:1); the ratio rule catches a bomb that sits
   under the size limits (5 MiB of zeros is about 1026:1).

The header sizes are attacker-controlled. A forged header that claims 100
bytes is caught as well: Python's `zipfile` stops at the declared size and the
CRC check then fails, which `safe_extract` reports as a corrupt entry. Nested
ZIPs are returned as bytes and never extracted recursively, and directory
entries are skipped.

## Trade-offs
- The limits are product decisions: an import of large images may need a
  higher per-entry limit, so make them per-endpoint settings rather than
  global constants.
- Files are kept in memory here to keep the example small. A real worker
  should stream each entry to disk (in a quota-limited temp directory) using
  the same counting loop.
- This problem only covers size. Entry names still need the path checks from
  problem 010 (`../` and absolute paths, "zip slip") before writing to disk.
- Other formats (tar.gz, 7z, gzip-encoded request bodies) need the same
  streaming limits; tar has no per-file data checksum, so count bytes there too.
- Running extraction in a separate process with a memory limit (cgroup or
  `resource.setrlimit`) is a good second layer: a missed case then kills one
  job, not the worker pool.

## Run
```bash
python -m unittest -v test_solution.py
```
