# 044 · A refresh token copied from a lost phone kept reading a customer's account for weeks after she got a new one

## Problem
A personal-finance app (about 400,000 mobile users) logs users in once and
then keeps them signed in with OAuth-style tokens: a 15-minute access token
and a 30-day refresh token. The refresh endpoint returned a new access token
and left the **same** refresh token valid, so the app sent one token for a
month until it expired and the user logged in again.

A customer lost her phone, which had a debugging build sideloaded by a
"friend" who copied the app's storage. She installed the app on a new phone
and kept using it. The copied refresh token went on minting access tokens for
the next four weeks; transaction history and linked-account details were read
from an unfamiliar IP range. The logs showed two clients refreshing the same
token every day, but the server had no rule that treated that as wrong. The
incident had to be reported to the regulator as a personal data breach.

## Root cause
**Reusable bearer refresh tokens (CWE-613, CWE-294).** A refresh token that
can be used any number of times is a long-lived password that anyone with a
copy can use, and the owner's continued use does nothing to push the copy
out. Because each use looked identical, the server could not notice that two
parties held it. Tokens were also stored in plain text, so a database leak
would have exposed them all (compare 041).

Related but different: 007 revokes sessions on password reset and 042 asks
for re-authentication before account changes. Neither helps when nobody
knows the token was copied.

## Solution
`solution.py` keeps `NaiveRefreshStore` and adds `RotatingRefreshStore`:

1. **Rotation.** Every refresh returns a new refresh token and marks the old
   one `used`. At any moment exactly one unused token exists per login.
2. **Families and reuse detection.** All tokens from one login share a
   family id. If a `used` token is presented again, two parties have copies,
   so the family is revoked (`RefreshTokenReuse`): its refresh tokens stop
   working and `authenticate` rejects its access tokens too. Whichever side
   refreshed first, the thief is locked out the next time the other side
   refreshes. The real user just logs in again, which starts a new family.
3. **Two expiries.** A refresh token unused for 30 days expires, and a family
   cannot be refreshed past 90 days from login, so rotation cannot keep a
   session alive forever.
4. **Digests at rest.** Only SHA-256 digests of tokens are stored; the tokens
   are 256-bit random values, so a fast hash is enough.
5. Other devices (other families) are unaffected by one family's revocation.

The tests use a fake clock and predictable fake tokens: with the original
store a stolen token keeps working through 29 daily refreshes by the owner;
with the fix reuse is detected whichever side goes first, an old token from
anywhere in the chain revokes the family, a 29-step rotation chain still
works, a token works 1 second before its 30-day expiry and not at it, and a
family refreshed every 20 days is refused at 90 days.

## Trade-offs
- **Races cause false alarms.** If the app fires two refreshes at once (two
  screens loading after waking up), the second looks like reuse and logs the
  user out. Clients should serialise refreshes; servers often allow a short
  grace period (for example 10-60 seconds) in which the previous token
  returns the same new pair instead of revoking. That window is also a small
  window for a thief, so keep it short.
- **Detection needs both parties to refresh.** If the owner stops using the
  app, the thief's chain continues until the 30-day idle or 90-day absolute
  limit. Showing active sessions and a "log out other devices" button, and
  alerting on reuse, close that gap.
- Every refresh is a database write, and the used-token records must be kept
  until they would have expired anyway so reuse can still be recognised.
- Alternatives and complements: sender-constrained tokens (DPoP, or mTLS
  bound tokens) make a copied token useless without the device's private key;
  storing tokens in the OS keystore makes copying harder in the first place.

## Run
```bash
python -m unittest -v test_solution.py
```
