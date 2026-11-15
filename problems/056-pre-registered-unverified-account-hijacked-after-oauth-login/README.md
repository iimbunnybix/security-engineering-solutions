# 056 · Customers who signed up with "Sign in with Google" found a stranger still logged in to their new account

## Problem
A project-management SaaS offers email + password sign-up and "Sign in with
Google". Several customers reported that boards they had just created were
being edited by someone else, and the "active sessions" page showed a
browser they did not recognise that had been logged in *before* they
ever signed up. Each affected account had been created with a password
days earlier, from that unknown browser, and the verification email had
never been clicked. When the real owner later used Google sign-in, the
app saw a matching email and attached Google to the existing account.

This is the "classic–federated merge" pre-account-hijacking attack
described by Sudhodanan and Paverd (USENIX Security 2022), which found
pre-hijacking flaws in dozens of popular services.

## Root cause
The OAuth callback did:

```python
account = accounts.get(identity.email) or create_account(identity.email)
account.link(identity)
```

Matching by email is reasonable *only if both sides proved they own that
mailbox*. The existing account had a password set by whoever signed up
first, and nobody had verified the email. Linking turned the attacker's
unproven account into the victim's real one, while the attacker's password
and open session kept working.

## Solution
`oauth_login`:

1. **Signs in an already-linked identity directly**, keyed by the
   provider's stable `(provider, sub)`, never by email.
2. **Links by email only if the provider says `email_verified`.** Without
   it, anyone could create a provider account claiming your address.
3. **Cleans an unverified account before linking**
   (`take_over_unverified_account`): the password nobody proved is deleted
   and every session is revoked. The victim keeps the account; the attacker
   loses every way in.
4. **Leaves verified accounts alone**: if the owner had verified the email,
   both credentials belong to the same person, so the password and existing
   sessions stay.

The tests run the attack against the naive callback (the attacker's
password and session still work) and against the fix (both are dead, the
victim's session works).

## Trade-offs
- Deleting the password surprises a real user who signed up, forgot to
  verify, then used Google. They can set a password again with "forgot
  password", which now goes to a verified address. Asking for the existing
  password before linking is the alternative, but the victim does not know
  the attacker's password, so it must be paired with "start fresh" anyway.
- Anything the attacker put into the account before linking (data,
  webhooks, API keys, invited members) is still there. Products with
  stronger needs should block unverified accounts from creating such
  things, or delete unverified accounts after a few days.
- Requiring `email_verified` refuses some providers or tenants that do not
  send the claim; those users must verify by email instead.
- `PBKDF2_ITERATIONS` is kept low so tests are fast; production should use
  OWASP's current figure (600,000 for PBKDF2-HMAC-SHA256) or Argon2/scrypt.

## Run
```bash
python -m unittest -v test_solution.py
```
