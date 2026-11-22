# 067 · Strangers showed up as members of customer workspaces after an invite link was forwarded

## Problem
A project-management SaaS lets workspace admins invite colleagues by email.
The email contains a link like `https://app.example/join?token=...`. A
customer's security team noticed accounts from unknown domains in their
workspace, reading roadmaps and pricing plans. Each had joined through an
invite link: one had been forwarded to a contractor's personal address,
another pasted into a public community chat ("use this to get in"), and an
old one was still valid in a former employee's mail archive. One link had
been used by several different accounts.

## Root cause
The invite token was a **bearer secret that was not bound to anyone**.
`NaiveInviteService.create_invite` recorded only `token -> workspace`; the
invited email was used to send the message and then forgotten. `accept`
added whichever signed-in account presented the token, never consumed the
invite and never expired it. Possession of the URL was the entire check, and
URLs leak: forwarding, chat, browser history, mail archives, link previews.
The raw tokens were also stored in the database, so a read-only leak of the
invites table would have given an attacker working links.

## Solution
`InviteService`:
- **Bound to an email.** The invite stores the invited address, normalised
  (trimmed and lower-cased). `accept` requires a signed-in account whose
  email matches it **and is verified**; otherwise anyone could sign up
  claiming the invited address.
- **Single use.** The invite is deleted before membership is granted, so
  the link cannot be replayed by a second account.
- **Wrong-account attempts do not consume it**, so a real invitee who
  clicked while signed in to another account can switch and still join.
- **Expiry and revocation.** Invites expire after 7 days; admins can revoke
  one at any time.
- **Only a hash is stored.** The server keeps `SHA-256(token)`; the token is
  32 random bytes from `secrets`, so hashing without a salt is enough (it
  cannot be guessed, only stolen).

The 13 tests reproduce a forwarded link and one link used by three
accounts, then cover the email binding, unverified look-alike accounts,
normalisation, single use, expiry boundaries, revocation and token hashing.

## Trade-offs
- Some teams invite a shared or distribution-list address, or people sign
  up with a different address than the one invited. Offer an admin approval
  step ("eve@elsewhere.example wants to join with an invite for asha@...")
  instead of loosening the check.
- Lower-casing the local part treats `Asha@` and `asha@` as one mailbox,
  which almost every provider does, but RFC 5321 allows them to differ.
  Do not strip dots or `+tags` unless you know the provider does.
- Domain-wide "anyone @acme.example can join" links are a separate feature
  and must check a verified email domain, not just possession of a link.
- The email itself still carries the token. Keep expiry short, show admins
  pending invites, and log who accepted each one so leaks can be audited.

## Run
```bash
python -m unittest -v test_solution.py
```
