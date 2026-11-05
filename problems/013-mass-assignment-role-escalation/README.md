# 013 · A free-tier user made himself an organisation admin by adding one field to the "edit profile" request

## Problem
A B2B SaaS app lets users edit their display name, bio and time zone with
`PATCH /api/users/me`. A security researcher on the bug bounty programme
opened the browser's dev tools, copied the request, and added
`"role": "admin"` to the JSON body. The response came back 200 and he was now
an admin of his organisation. Adding `"org_id": <another id>` moved his
account into a different customer's organisation, and
`"credit_cents": 10000000` gave him prepaid credit. The same endpoint also
returned `password_hash` in its response.

## Root cause
**Mass assignment** (OWASP API Security Top 10: "Broken Object Property
Level Authorization"). The handler copied every key in the request onto the
user model:

```python
for key, value in body.items():
    if hasattr(user, key):
        setattr(user, key, value)
```

The code authorised *which user* could be edited (only yourself) but not
*which properties*. Every column on the model was writable by every user,
with any type (`"marketing_opt_in": "yes please"` was stored as a string).
The response had the same problem in reverse: it serialised the whole model.

## Solution
`solution.py`:

- **An input allowlist per endpoint.** `PROFILE_UPDATE` declares the only
  four fields a user may edit, with exact types (`True` is not accepted as an
  int, `"true"` is not a bool), lengths, choices and a printable-characters
  check. Anything else is rejected with a 400 that names the unknown fields,
  and nothing is changed when any field is invalid.
- **Privileged fields behind a separate endpoint and permission.**
  `admin_update_user` accepts only `role` and `email_verified`, only for an
  admin of the same organisation, and an admin cannot change their own role.
  Fields such as `credit_cents` and `org_id` are not writable through any user
  facing schema; they change only through billing and support flows.
- **An output allowlist.** `serialize` returns public fields to other users
  and a slightly larger set to the user themselves. `password_hash` and
  `credit_cents` are never in either.
- **Audit entries** for every field that actually changed.
- `strict=False` drops and logs unknown fields instead of rejecting, for
  rolling out the schema without breaking clients that send extra fields.

The tests replay the attack against the old handler (role, verification,
credit and org all change) and against the fixed one (400, nothing changes,
nothing audited), and cover type confusion, limits, cross-user and
cross-organisation edits, and response filtering.

## Trade-offs
- Allowlists must be maintained: a new editable field needs a schema change.
  That is the point; making a field writable becomes a reviewed decision.
- Strict rejection can break old clients that send read-only fields back
  (for example the whole object from a previous GET). Start in lenient mode,
  watch the log, then switch to strict.
- Framework features do the same job: Pydantic/DRF serializers with explicit
  fields, Rails strong parameters, `@JsonIgnoreProperties` in Jackson. Never
  bind request bodies directly to ORM models.
- A blocklist (`del body["role"]`) looks simpler but fails open: every new
  sensitive column is writable until someone remembers to block it.

## Run
```bash
python -m unittest -v test_solution.py
```
