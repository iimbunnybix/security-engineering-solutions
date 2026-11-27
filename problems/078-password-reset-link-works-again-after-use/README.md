# 078 · A customer's password was changed again 10 minutes after she reset it herself, from the same reset link

## Problem
An online pharmacy sends a "reset your password" email with a link
containing a random 43-character token, valid for one hour. A customer
reset her password from a library computer, closed the tab and left. The
next person at that computer opened the browser history, clicked the same
link, set a new password and ordered to a new address with her saved card.

Support found the pattern repeated: in one month, 37 accounts had two
successful resets from the same token, minutes apart. Other cases came from
reset emails forwarded to a family member and from a corporate proxy whose
URL logs were readable by the IT team. The team had already moved to random
tokens and a one-hour expiry after an earlier incident (problem 012), so
everyone assumed reset links were safe.

## Root cause
**The token was checked for existence and expiry, but never used up
(CWE-640, weak password recovery).** `reset_password` looked the token up,
checked the clock and set the password, then left the token in place. A
link was a reusable "set any password" credential for its whole hour, for
anyone who ever saw the URL. Two more gaps made it worse:

- Clicking "forgot password" twice made two tokens; using one left the
  other valid, so an older link could undo the password just chosen.
- Raw tokens sat in the database, so anyone reading that table (a replica,
  a backup) could reset any account with a pending link.

Problem 012 was guessable tokens and problem 007 was sessions surviving a
reset; here the token is strong and expires, but it can be replayed.

## Solution
`solution.py` keeps `OriginalResetService` and adds `ResetService`:

1. **Store only `sha256(token)`.** The raw token exists only in the email.
   A random 32-byte token does not need a slow hash.
2. **Claim the token atomically on first use.** `claim_token` checks
   "exists, unused, not expired" and sets `used = True` in one step under a
   lock. In a database this is
   `UPDATE reset_tokens SET used_at = now() WHERE token_hash = ? AND used_at IS NULL AND expires_at > now()`
   and the reset continues only if one row changed. The test fires 20
   threads at the same token at once; exactly one wins.
3. **Invalidate every other reset token of the user when the password
   changes**, both via reset and via the logged-in "change password" form.
4. **Keep the one-hour expiry.** A link works at 59 min 59 s and fails at
   60 min.
5. A too-short new password is rejected *before* the token is claimed, so a
   typo does not burn the link.

## Trade-offs
- **A claimed link is gone even if the request then fails** (for example
  the database write for the password times out). The user has to ask for a
  new email. That is the safe direction; doing claim and password update in
  one database transaction avoids it.
- **The lock here is per process.** With several web servers, the
  compare-and-set must happen in the shared database (the conditional
  `UPDATE` above), not in application memory.
- **Single-use does not stop the first click by someone else.** Email
  security scanners that pre-fetch links are a reason to make the link
  open a form (GET) and only claim the token on the form submit (POST).
  Shorter lifetimes (15-30 min) and logging out other sessions after a
  reset (problem 007) reduce exposure further.
- **Used rows pile up.** Delete rows past expiry with a periodic job.

## Run
```bash
python -m unittest -v test_solution.py
```
