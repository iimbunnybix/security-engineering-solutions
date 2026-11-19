# 064 · Credential-stuffing bots logged in to thousands of brand-new accounts on the first try with "Password1"

## Problem
A food-delivery app saw a wave of account takeovers on accounts created in
the previous few months: saved cards were used for orders to unknown
addresses. The login logs showed bots trying one or two passwords per
account from lists of leaked credentials, and succeeding on the first
attempt for a large share of new users.

The sign-up rules looked strict: at least 8 characters, an upper-case
letter, a lower-case letter and a digit. Yet the passwords the bots got in
with were `Password1`, `Welcome@123` and similar.

## Root cause
Composition rules measure what a password is **made of**, not whether
attackers already **know it**. `Password1` and `Welcome@123` satisfy every
rule (`naive_password_ok` accepts both) and are among the most common
passwords in public breach dumps, which are the first thing credential
stuffing tools try. Meanwhile the rules rejected a long passphrase such as
`correct horse battery staple` for lacking a digit. NIST SP 800-63B
recommends exactly the opposite: no composition rules, but checking new
passwords against lists of commonly used and compromised passwords.

## Solution
`check_new_password(password, username, service)`:

1. **Length, not composition:** at least `MIN_PASSWORD_LENGTH` (12)
   characters, and the password must not contain the username.
2. **Breach check with k-anonymity:** compute the SHA-1 of the password,
   send only the first **5 hex characters** to the range service, receive
   every breached hash suffix with that prefix and its count, and look for
   our suffix locally. The service never sees the password or its full hash
   (a 5-character prefix is shared by many breached hashes, so it does not
   identify one). Any match is rejected with the number of breaches.
3. **Outage behaviour:** if the service is unreachable, a small built-in
   list of the most common passwords is checked and anything else is
   accepted with `breach_checked=False`, so the account can be re-checked at
   its next login instead of the check being silently skipped.

`FakeBreachRangeService` stands in for a real range API (Have I Been
Pwned's Pwned Passwords range endpoint works this way) and records the
prefixes it was asked for, so the tests can prove only 5 characters left.

## Trade-offs
- The real corpus is large (hundreds of millions of hashes). Calling a
  hosted range API adds latency and a third-party dependency to sign-up; the
  alternative is downloading the corpus and serving the range lookups
  internally.
- A breach check only stops **known** passwords. It does not replace rate
  limiting, MFA, or checking at login whether a user's current password has
  since appeared in a breach.
- Rejecting a password with "seen in 12 breaches" can confuse users; the UI
  should explain that other people used it, not that their account leaked.
- SHA-1 is fine here because it is only a lookup key into a public list.
  The password is still stored with a slow hash (bcrypt, scrypt, Argon2).

## Run
```bash
python -m unittest -v test_solution.py
```
