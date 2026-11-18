# 061 · A 100 KB request of nothing but "[" characters turned the drafts API into a wall of 500 errors

## Problem
A writing app exposes `POST /drafts`, which accepts a JSON document (title,
blocks, tags) of up to 1 MB. One evening the error tracker filled with
thousands of `RecursionError` stack traces per minute, the on-call engineer
was paged for a 500-rate alert, and real users saving drafts saw intermittent
failures while workers spent their time building and logging huge tracebacks.

The requests came from a handful of IPs and were tiny by the API's standards:
bodies of about 100 KB made of `[` characters, and a second variant with
5,000 properly closed levels of `[[[...]]]`. No authentication was needed to
reach the parser, so this was a cheap, repeatable denial-of-service.

## Root cause
Two recursive steps ran on attacker-controlled structure with no depth limit:

- `json.loads` recurses once per nesting level. On the Python 3.13 used here,
  `"[" * 100_000` raises `RecursionError` inside the parser.
- A body nested 5,000 deep parses fine, but the app's recursive `strip_html`
  walker then exceeds Python's default recursion limit of 1000.

The handler only caught `json.JSONDecodeError`. `RecursionError` is a
`RuntimeError`, not a `ValueError`, so it escaped to the framework as a 500,
with a full stack trace logged and reported for every request. The 1 MB body
limit did not help: depth costs one byte per level.

## Solution
`parse_limited_json` checks nesting depth **before** parsing:

- `max_nesting_depth` is a plain loop over the characters. It counts `[`/`{`
  and `]`/`}`, ignores brackets inside strings (tracking quotes and
  backslash escapes), and returns as soon as the depth passes the limit, so
  an attack body is rejected after reading only a few dozen characters.
- Bodies nested deeper than `MAX_NESTING_DEPTH = 32` raise `TooDeeplyNested`,
  which the handler turns into a 400.
- Because accepted documents are at most 32 deep, the recursive sanitiser and
  `json.dumps` can never get near the recursion limit.
- The handler catches `ValueError` (which covers `JSONDecodeError`) so every
  malformed body is a client error, not a 500.

## Trade-offs
- The scan reads the body twice (once to count, once to parse). It is a
  linear pass and stops early on attacks, but for very large bodies a
  streaming parser with a built-in depth limit avoids the second pass.
- 32 is a policy choice. Legitimate deeply nested data (some ASTs, nested
  comment trees) needs a higher limit or a flatter schema.
- The scanner only counts brackets; it does not validate JSON. Malformed
  bodies are still caught by `json.loads` afterwards.
- Raising `sys.setrecursionlimit` is not a fix: it moves the crash point and
  can overflow the C stack and kill the whole process instead.
- Depth is one of several limits worth enforcing (body size, number of keys,
  string length, array length); schema validation libraries can apply them
  together.

## Run
```bash
python -m unittest -v test_solution.py
```
