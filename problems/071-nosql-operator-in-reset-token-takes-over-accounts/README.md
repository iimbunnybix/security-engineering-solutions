# 071 · Accounts were taken over through "forgot password" by sending {"$ne": null} as the reset token

## Problem
A ticketing web app (Node-style JSON API backed by a MongoDB-like document
store, about 400k customer accounts) let users reset a forgotten password:
`POST /forgot` emails a random token, and `POST /reset` takes
`{"email", "token", "new_password"}` as JSON. Over one weekend support
received dozens of "I can't log in and my saved card was used" tickets.
The access logs showed the same pattern for every victim: one `/forgot` for
the victim's email from an unknown IP, then one `/reset` a second later from
the same IP, long before the real email could have been read. Resale-ticket
fraud on the hijacked accounts had to be refunded, and every account with a
reset in that window was locked and contacted.

## Root cause
The handler built the query from the body as-is
(`naive_complete_reset`): `find_one({"email": body["email"], "reset_token": body["token"]})`.
It assumed `token` was a string, but JSON can send an object, and the
document store reads an object in a query as **operators**. A body with
`"token": {"$ne": null}` asks for "a user with this email whose reset token
is not null", which is true right after the attacker triggers `/forgot` for
the victim. `{"$regex": "."}` works the same way, and
`"email": {"$gt": ""}` even removes the need to know the email: it takes the
first account with a pending reset. This is query injection without any
string concatenation: the injected *type* changes the query's meaning.
`ReproduceProblem` shows all three bodies resetting the victim's password.

## Solution
- **Validate the body before touching the database** (`parse_reset_body`):
  exactly the fields `email`, `token`, `new_password`, each a non-empty
  `str` of at most 256 characters; anything else (a dict, list, number,
  extra field such as `role`) is a 400. This is what blocks every operator.
- **Look up by email only, check the token in code** (`token_is_valid`):
  the stored token must be a string, not expired (30 minutes) and equal
  under `hmac.compare_digest`. Even if a future field slipped past the
  schema, the secret comparison no longer happens inside the query.
- **Single use**: the token is cleared after a successful reset.
- One generic `ResetRefused` for unknown email, wrong token and expired
  token, so the endpoint does not reveal which accounts exist.

## Trade-offs
- Type checks must cover every route that builds a query from JSON (login,
  search filters, API-key lookups), not only this one. Schema validation
  at the framework edge (JSON Schema, Pydantic, `express-mongo-sanitize`
  stripping `$` keys) makes that the default instead of a per-handler habit.
- Stripping `$`-keys alone is weaker than strict types: a list value or a
  differently named operator syntax in another store can still change a query.
- Storing reset tokens hashed (as with passwords) would also protect them if
  the database leaks; this example keeps them in plain form to stay short.
- MongoDB can also be told to refuse server-side JavaScript (`$where`), which
  removes the worst operator, but does not stop `$ne`/`$regex`/`$gt`.

## Run
```bash
python -m unittest -v test_solution.py
```
