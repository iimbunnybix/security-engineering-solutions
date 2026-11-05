# 017 · Signup API stopped responding when a bot submitted a few odd-looking email addresses

## Problem
A consumer app's signup endpoint validated the email field with a regex copied
from a forum answer:

```
^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$
```

It worked for every real address. One evening the API pods hit 100% CPU and
health checks started timing out. The access log showed a bot posting signup
requests whose email field was a long run of letters ending in `!`, with no
`@` at all. Each such request held a worker thread busy for seconds to
minutes, so a handful of requests per second was enough to take signup (and
everything else served by the same pods) offline. No credentials or data were
exposed; the attack cost nothing but availability, and it needed no volume to
work.

## Root cause
- **A nested quantifier in a backtracking regex engine (ReDoS).** The group
  `([...]+)` is itself repeated with `+`. A run of *n* letters can be split
  between the inner and outer `+` in 2^(n-1) ways. When the match finally fails
  (no `@`), Python's `re` engine backtracks through every split before giving
  up.
- Measured with the original pattern on `"a" * n + "!"`: 16 characters ≈ 3 ms,
  18 ≈ 10 ms, 20 ≈ 43 ms, 22 ≈ 175 ms. Each extra character roughly doubles
  the time; extrapolating, a 30-character string would take tens of seconds.
- **No length limit before validation.** The cost of a request was decided by
  the attacker.

## Solution
`is_valid_email` in `solution.py`:

1. **Cap the length first** (254 characters for the address, 64 for the local
   part, 63 per domain label, from RFC 5321 / DNS limits). Anything longer is
   rejected before any pattern runs, so every request has a bounded cost.
2. **Split the structure with plain string operations** — exactly one `@`,
   domain split on `.` — instead of encoding the structure in one big regex.
3. **Check each piece with a single character class and one quantifier**
   (`[A-Za-z0-9_.+%-]+`, `[A-Za-z0-9-]+`). With nothing nested, a match can only
   move forward, so the work is linear in the length.
4. Extra rules that the original regex expressed badly are now explicit
   if-statements: no leading/trailing/double dots in the local part, no label
   starting or ending with `-`, an alphabetic top-level domain of 2+ letters.

On the same inputs the new validator takes a few microseconds, and a
1,000,000-character input is rejected by the length check in microseconds.

## Trade-offs
- This is a *practical* validator, not full RFC 5322 (quoted local parts,
  comments, IP-literal domains are rejected). That is the usual product choice;
  the only real proof an address works is sending a confirmation email.
- Internationalised addresses (non-ASCII local parts, IDN domains) are
  rejected. Supporting them means punycode-encoding the domain with the `idna`
  codec and widening the local-part character set.
- Alternatives: a regex engine with guaranteed linear time (RE2 via
  `google-re2`), or a per-request timeout on validation. RE2 needs a third-party
  package; timeouts limit the damage but still burn CPU up to the limit.
- The timing tests use ratios rather than absolute times for the original
  pattern so they stay stable on slow CI machines.

## Run
```bash
python -m unittest -v test_solution.py
```
