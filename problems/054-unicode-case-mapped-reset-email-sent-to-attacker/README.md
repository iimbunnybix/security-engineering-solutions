# 054 · Password reset links for real users were delivered to an attacker's lookalike email address

## Problem
A developer platform with a few million accounts saw a cluster of account
takeovers. Each victim's audit log showed a normal "forgot password" request,
a reset, and then new SSH keys added. None of the victims had received a
reset email. The mail logs showed the links had gone to addresses such as
`mike@gıthub.test`, at a domain the attacker had registered, while the
victim's real address was `mike@github.test`. The two differ only in the
dotless `ı` (U+0131). The same class of bug was publicly disclosed in 2019
against a large code-hosting site.

## Root cause
The handler did two things that are each fragile and together fatal:

```python
if account.email.upper() == typed_email.upper():
    send_reset_link(typed_email, token)
```

- **Lossy case comparison.** Unicode case mapping is not one-to-one:
  `"ı".upper()` is plain `"I"`, so `"mike@gıthub.test".upper()` equals
  `"MIKE@GITHUB.TEST"`. Many different strings compare equal after `upper()`.
- **Mail went to the typed address**, not the stored one. The lookup
  rule decided *which account*, but the attacker's own string decided
  *where the link went*.

`ReproduceProblem` shows both: the lookalike compares equal, and the
victim's reset link lands in the attacker's mailbox.

## Solution
- **Always send to the stored address.** The typed value is only a lookup
  key. Whatever it matches, the link goes to the mailbox the owner verified.
  This alone defeats the attack, and it keeps working if the matching rule
  is changed later.
- **Look up by a canonical key built with NFKC + `casefold()`**, the Unicode
  rule meant for caseless matching. `casefold()` keeps `ı` distinct from `i`,
  so the lookalike finds no account. NFKC still lets harmless variants
  match (case differences, full-width letters, the Kelvin sign `K`), and the
  tests check that those still mail only the stored address.
- **Duplicate keys are refused** when the index is built, rather than
  silently picking one account.
- Unknown emails send nothing and return the same way, so the endpoint does
  not reveal which emails have accounts.

## Trade-offs
- The canonical key must be computed the same way at sign-up and stored
  with a UNIQUE index; otherwise two accounts can share a key
  (`backend-api-solutions` problem 020 covers that side).
- Folding with NFKC makes some different-looking strings match. That is
  safe here only because mail goes to the stored address; never reuse this
  key to *display* or *contact* anyone.
- Internationalised domains also reach mail servers as punycode
  (`xn--...`); comparing punycode forms is an alternative, but it does not
  remove the need to send to the stored address.
- Confusable detection (Unicode TR39 skeletons) could additionally flag
  lookalike sign-ups, but it needs data files beyond the standard library.

## Run
```bash
python -m unittest -v test_solution.py
```
