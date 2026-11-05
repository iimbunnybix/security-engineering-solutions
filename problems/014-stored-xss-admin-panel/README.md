# 014 · Support agents' accounts started closing tickets and issuing refunds on their own after opening one customer's ticket

## Problem
A marketplace's internal support console lists tickets with the customer's
display name, the ticket subject and a link to the customer's website. A
customer changed his display name to an `<img src=x onerror=...>` tag and
opened a ticket. Every agent who opened the ticket list ran his script: it
read the page's CSRF token and called the console's own API to issue refunds
to his account and mark tickets as resolved. Nothing on the server looked
unusual because every request came from a logged-in agent's browser.

The pentest that followed found two more holes in the same page: a ticket
subject containing `"><script>` escaped the `title` attribute, and a website
of `javascript:...` ran when an agent clicked "site".

## Root cause
**Stored cross-site scripting.** The console built HTML with f-strings and
inserted customer-controlled values without encoding:

```python
f'<td class="name">{t["display_name"]}</td>'
f'<td title="{t["subject"]}">'
f'<a href="{t["website"]}">'
```

Each place needs a different defence: HTML text and attributes need entity
encoding, URLs need a scheme allowlist (escaping does not make
`javascript:alert(1)` safe), and data inside `<script>` needs JavaScript
string encoding (HTML escaping is wrong there, and a raw `</script>` closes
the element). There was also no Content-Security-Policy, so any injected
inline script ran.

## Solution
`solution.py`:

- **`Template` escapes every placeholder by default.** `{{ v }}` uses
  `html.escape(quote=True)`, safe for text and quoted attributes. Developers
  have to opt *out* explicitly, and `|safe` only accepts `SafeHTML` objects
  produced by code (for example another rendered template), never strings.
  Unknown filters are errors so a typo cannot disable escaping.
- **`|url`** keeps only `http`, `https`, `mailto` and relative URLs. It
  first strips the control and whitespace characters browsers ignore, so
  `java\tscript:`, ` javascript:` and `JaVaScRiPt:` are caught, and rejects
  protocol-relative `//host` links. Everything else becomes `#`.
- **`|js`** emits JSON with `<`, `>`, `&`, U+2028 and U+2029 escaped, so a
  value containing `</script>` cannot end the script block.
- **`csp_header`** builds a nonce-based policy (`script-src 'nonce-...'
  'strict-dynamic'; object-src 'none'; base-uri 'none'`) as a second layer:
  if an escaping mistake slips through, injected inline scripts still do not
  run.

The tests parse the rendered HTML with `html.parser` (as a browser would
build the DOM) and check that none of the payloads creates an element or an
`on*` attribute, that the payload text is displayed exactly as typed, that
ten `javascript:`/`data:`/`vbscript:`/protocol-relative variants become `#`,
and that there is exactly one `<script>` element on the page with the
expected nonce.

## Trade-offs
- In production, use your framework's auto-escaping (Jinja2 with
  `autoescape=True`, Django templates, React JSX) instead of a home-made
  template, and ban string-built HTML in code review. This module shows what
  those engines do and why each context is different.
- If users must submit rich text (formatted ticket bodies), escaping is not
  enough: sanitise with an allowlist HTML sanitiser (for example
  `nh3`/`bleach` on the server, DOMPurify in the browser).
- CSP with nonces needs every legitimate inline script to carry the nonce,
  which takes work for old pages. Start with `Content-Security-Policy-Report-Only`
  and fix the reports before enforcing.
- `HttpOnly` cookies stop scripts from reading the session cookie, but do not
  stop an injected script from calling the API as the user, which is what
  happened here. They are not an XSS fix.
- Internal tools are a common blind spot: they render data from customers
  and are used by staff with powerful permissions.

## Run
```bash
python -m unittest -v test_solution.py
```
