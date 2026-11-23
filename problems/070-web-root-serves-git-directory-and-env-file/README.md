# 070 · A scanner downloaded the marketing site's .git folder and .env file, including a deploy token and a payment API key

## Problem
The company's marketing site is a static site built from a Git repository.
The deploy script logged into the web server, ran `git pull` in
`/var/www/site` and the web server's document root pointed at that
directory.

A bug-bounty researcher reported that `https://www.example.com/.git/config`
and `https://www.example.com/.env` returned the files. The Git config held
the remote URL with an embedded CI deploy token, which could push to the
repository; `.env` held a live payment-provider API key used by the
site's contact form. With `/.git/` readable, tools that walk Git objects
can rebuild the entire repository history, including secrets that were
"deleted" years ago. Both credentials had to be rotated, and the access logs
showed automated scanners requesting `/.git/HEAD` daily for months.

## Root cause
The **web root was the repository checkout**, so the server published
every file in it (`naive_serve`). There was no path traversal: `/.env` and
`/.git/config` were simply inside the directory being served, next to
`index.html`. Hidden files are hidden from `ls`, not from HTTP. The source
files and `README.md` were public too.

## Solution
Two independent layers, so one mistake does not expose secrets:

1. **Publish an allowlist, not a directory** (`plan_publish`, `publish`).
   The deploy copies only built asset types (`.html`, `.css`, `.js`,
   images, fonts, `.txt`) into the web root. Source and docs are skipped.
   Any hidden path (`.git/`, `.env`, `assets/.DS_Store`) or well-known
   credential name (`id_rsa`, `terraform.tfstate`) **fails the deploy**
   with the list of offending files, instead of being silently dropped,
   so someone fixes the build.
2. **The server refuses hidden paths anyway** (`serve`). After
   percent-decoding and normalising dot segments, any path segment that
   starts with `.` gets **404**, the same answer as a missing file, so
   scanners cannot tell what exists. `/%2egit/config` and
   `/assets/../.env` are caught too. Only a leading `/.well-known/` is
   allowed (used for `security.txt` and ACME certificate challenges).

## Trade-offs
- The extension allowlist must be updated when the site adds a new asset
  type (`.webp`, `.json`); until then those files are skipped and show up
  as broken pages, which is a visible, safe failure.
- Layer 2 blocks dot-files by name only. Secrets in normal-looking files
  (`config.js` with a key in it) need secret scanning in CI (see problem
  002). Never put server-side secrets in a static site's build at all.
- On case-insensitive file systems (`/.GIT/`) the name check still works
  because every hidden segment starts with `.`, but a check for a specific
  name such as `.git` would not; block by the leading dot, as here.
- Better still: deploy the build output to object storage or a CDN rather
  than running `git pull` on a server, so the repository never exists on a
  machine that serves HTTP. After an exposure like this, rotate every
  secret that was ever in the repository's history, not only the current
  ones.

## Run
```bash
python -m unittest -v test_solution.py
```
