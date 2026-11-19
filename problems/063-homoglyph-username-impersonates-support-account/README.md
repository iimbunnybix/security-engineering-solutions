# 063 · Buyers paid "verification fees" to an account called "suppоrt" that looked exactly like the real support team

## Problem
A second-hand marketplace lets buyers and sellers message each other. The
staff account is called `support`, and `admin`, `support`, `security`,
`help` and `official` are reserved at sign-up. Usernames are unique
case-insensitively.

A scam ring registered `suppоrt` (with a Cyrillic `о`), `ѕupport` (Cyrillic
`ѕ`) and `sup<U+200B>port` (an invisible zero-width space after `sup`). In the app's font all
three look exactly like `support`. They messaged sellers about "account
verification", took small payments and harvested logins; the trust and
safety team found dozens of victims before the accounts were banned, and
new variants appeared the next day.

## Root cause
`naive_is_available` compared strings: `casefold(new) == casefold(existing)`.
Different code points are different strings, even when they render
identically:

- Cyrillic `о` (U+043E) is not Latin `o` (U+006F),
- full-width `ｓｕｐｐｏｒｔ` is not `support`,
- a zero-width space (U+200B) is invisible but still a character,
- `rahu1` (digit one) looks like `rahul` in many fonts.

The check answered "is this the same string?" while the real question was
"could a person mistake this for that name?".

## Solution
`UsernameRegistry` compares names by **skeleton** (the idea of Unicode
UTS #39):

1. `skeleton()`: NFKC-normalise (full-width -> normal), case-fold, delete
   format characters (`Cf`: zero-width spaces and joiners, bidi marks), and
   map look-alike characters to the Latin letter they imitate (`а`->`a`,
   `ѕ`->`s`, `0`->`o`, `1`->`l`, ...).
2. Reserved names are stored as skeletons; a new name whose skeleton equals
   one is rejected. Existing users are indexed by skeleton too, so `rahu1`
   collides with `rahul` and `Priya` with `priya`.
3. Names with invisible characters, or with letters from more than one
   script (Latin plus Cyrillic), are rejected outright: a real person's name
   almost never mixes alphabets.

Names in one non-Latin script (`иван`) and accented Latin names (`josé.m`)
are still accepted, and the name is stored as typed for display.

## Trade-offs
- The mapping table is a small sample. Production code should use the full
  `confusables.txt` from Unicode (thousands of entries, including
  multi-character look-alikes such as `rn` for `m`) or a library that
  implements UTS #39, and the script of a character should come from the
  Unicode Script property rather than the character name.
- Skeleton matching blocks some honest names: a user who wants `rahu1`
  while `rahul` exists has to pick something else. That is usually an
  acceptable price for messaging platforms.
- The UI is the second line of defence: show a verified badge on staff
  accounts and warn when someone who is not staff mentions payments or
  "verification" in a first message.

## Run
```bash
python -m unittest -v test_solution.py
```
