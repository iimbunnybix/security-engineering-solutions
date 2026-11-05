# 034 · Moderators who clicked a seller's profile picture to enlarge it had their account email changed to the attacker's

## Problem
A second-hand marketplace (about 1.2 million sellers) lets every seller upload
a profile picture, shown on listings and in the moderation queue. Clicking the
picture opens the full-size file at `https://shop.example.test/media/avatars/<name>`.
Over one weekend, several moderators found they could no longer log in: their
account email had been changed to addresses at a throwaway mail provider and a
password reset had been completed from there. The attacker then used the
moderator accounts to approve scam listings and unban their own sellers. Every
affected moderator had opened the full-size avatar of the same new seller
shortly before. The "avatar" was an SVG file containing a `<script>` that
called the change-email API.

## Root cause
**Stored XSS through file upload.** `NaiveAvatarStore` made three decisions
from attacker-controlled input and served the result from the main site:

- **Type check on the client's claim.** Any upload whose declared
  Content-Type started with `image/` was accepted. `image/svg+xml` is an
  image type, and SVG is an XML document that may contain `<script>` and
  event handlers.
- **Content-Type from the uploaded file name.** The file was served with the
  type `mimetypes.guess_type` derived from the client's name, so
  `avatar.svg` went out as `image/svg+xml` and `cute-cat.html` (declared as
  `image/png`) went out as `text/html`. Both render as documents when opened
  directly.
- **Same origin, no protective headers.** The files were served from
  `shop.example.test`, the origin that holds the session cookie, with no
  `X-Content-Type-Options: nosniff`, no `Content-Disposition` and no CSP. Any
  script in them ran as the viewer, with their cookies and the ability to read
  CSRF tokens. Without `nosniff`, even a vague type such as `text/plain` can
  be sniffed as HTML by some browsers.

An `<img src=…>` tag does not run script inside an SVG, so the listings looked
harmless; the attack only fired when someone opened the file itself. The
tests reproduce all three paths against the naive store with a simplified
browser model (`browser_runs_script`).

## Solution
`AvatarStore` in `solution.py`:

- **Allowlist by content, not by claim.** `detect_raster_type` reads the
  magic bytes and accepts only PNG, JPEG, GIF and WebP; the declared type and
  the file name are ignored. SVG is rejected. Empty files and files over
  1 MiB are rejected too.
- **Server-chosen names.** Files are stored as `<128-bit random hex>.<ext>`
  with the extension from the detected type, so the client cannot pick
  `.html`, path segments or another user's file name.
- **Safe response headers** (`safe_headers`): `Content-Type` from detection,
  `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` (an
  `<img>` ignores it, so avatars still display, but opening the URL
  downloads the file instead of rendering it) and
  `Content-Security-Policy: default-src 'none'; …; sandbox`, which blocks
  script even if a document is rendered.
- **Separate origin.** Avatars are served from
  `usercontent.example-cdn.test`, a different site with no session cookies.
  If every other layer failed, script there could not act as the user on the
  shop.

A PNG with an HTML payload appended (a polyglot) is accepted, as its bytes do
start with a PNG signature, but it is served as `image/png` with `nosniff`
from the other origin and does not run. The tests also check that each of
`attachment` and `sandbox` alone stops the SVG in the model, while `nosniff`
alone does not, since an SVG declared as `image/svg+xml` is not being
sniffed.

## Trade-offs
- **No SVG avatars.** If vector uploads are required, sanitising SVG
  (removing scripts, event handlers, `foreignObject`, external references) is
  hard to get right; rasterise the SVG server-side in a sandboxed worker and
  store only the PNG instead.
- **Magic bytes prove a prefix, not a valid image.** Re-encoding uploads
  (decode and re-save with an image library) strips appended payloads and
  metadata such as GPS EXIF data, and catches malformed files that target
  image decoders. That needs a third-party library, so it is not done here.
- **The separate origin must be a separate site**, not a subdomain of the
  shop (`media.shop.example.test` would share cookies set for the parent
  domain and count as same-site). It costs a DNS name, a certificate and CDN
  config.
- `browser_runs_script` is a deliberately simple model of browser rules; real
  sniffing and rendering differ between browsers, which is why the fix stacks
  several independent layers instead of relying on any one of them.
- Existing uploads must be migrated: re-validate stored files, move them to
  the new origin and delete anything that is not a raster image.

## Run
```bash
python -m unittest -v test_solution.py
```
