# 065 · Accounts were taken over through password-reset links the owners had requested but not yet used

## Problem
An online shop's support team got complaints from customers who had asked
for a password reset, opened the email, and found minutes later that their
password had already been changed and saved addresses edited. Nobody had
phished them and the reset emails had gone to the right inboxes.

The reset page lived at `https://accounts.shop.example/reset?token=...`. Like
every page on the site, it loaded an analytics tag, a chat widget and an ad
pixel from three outside vendors, and the site sent
`Referrer-Policy: unsafe-url` so marketing could see full landing URLs. A
contractor with read access to one vendor's request logs found the full
reset URLs, tokens included, sitting in the `Referer` column and used the
ones that were still unexpired.

## Root cause
A secret in a URL does not stay where you put it. When a page loads a
script, image or iframe, the browser sends a `Referer` header whose content
is decided by the page's Referrer Policy. Under `unsafe-url` (and under the
older browser default `no-referrer-when-downgrade`, for any HTTPS
destination) that is the **full URL including the query string**. In the
model in `solution.py`, `naive_reset_page` produces three third-party
requests, and every one carries `token=...` in its Referer. Even the modern
default `strict-origin-when-cross-origin` would still send the full URL to
same-origin resources and leaves the token in browser history, and any
third-party script on the page can read `location.href` directly.

## Solution
1. **A model of the browser's Referer computation** (`referer_for`), per the
   W3C Referrer Policy spec: userinfo and fragment are always removed; a URL
   longer than 4096 characters is cut to its origin; then `no-referrer`,
   `origin`, `strict-origin`, `strict-origin-when-cross-origin`,
   `origin-when-cross-origin`, `no-referrer-when-downgrade`, `same-origin`
   and `unsafe-url` apply their same-origin and HTTPS-to-HTTP downgrade
   rules. `parse_policy_header` lets the last recognised token in the header
   win and falls back to `strict-origin-when-cross-origin`.
2. **The token never sits on a page that loads anything.** The email link
   goes to `/reset/start?token=...`. That endpoint looks up the token's
   SHA-256 hash, removes it (single use, 30-minute lifetime), creates a
   random reset session stored as a hash, and replies `303 See Other` to
   `/reset` with a cookie that is `HttpOnly; Secure; SameSite=Strict`,
   scoped to `Path=/reset` and valid for 10 minutes. The redirect response
   loads no resources and itself carries `Referrer-Policy: no-referrer`.
3. **The form page is clean.** `/reset` is served with
   `Referrer-Policy: no-referrer` and `Cache-Control: no-store`, loads only
   same-origin files, and the session is deleted as soon as the new password
   is saved.

The 26 tests show the naive page leaking the token to all three vendors,
the fixed flow sending no Referer at all, and the policy edge cases
(downgrade, port differences, fragments, over-long URLs, header parsing).

## Trade-offs
- Removing analytics from the reset pages loses funnel data for them. Count
  resets on the server instead.
- The link becomes useless after the first click, including clicks by email
  security scanners that pre-fetch links. Some teams show a "Continue"
  button on `/reset/start` (a POST does the exchange) to survive scanners.
- The 10-minute session means a user who walks away must request a new
  email.
- `Referrer-Policy: no-referrer` is a second layer, not the fix: it does not
  stop a third-party script from reading the URL, which is why the token is
  moved out of the URL and third-party scripts are removed.

## Run
```bash
python -m unittest -v test_solution.py
```
