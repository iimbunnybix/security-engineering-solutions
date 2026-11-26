# 075 · The orders API's 500 error page showed anyone the production database password

## Problem
An orders API used an error-handling middleware written during early
development: on any unhandled exception it returned HTTP 500 with
`traceback.format_exc()` in the JSON body, "so the mobile team can debug".
Nobody removed it before launch.

During a brief database failover, a security researcher noticed that
`GET /orders/<id>` returned a traceback whose last line was
`ConnectionError: could not connect to postgresql://orders_app:<password>@db-primary.internal:5432/orders`.
The response also showed internal hostnames, source file paths and the
names of the libraries in use. The password had to be rotated across every
service that shared it, the incident was reported to customers as a
potential exposure, and the researcher was paid a bounty.

## Root cause
**Internal error details were sent to the client.** Exception messages are
written for developers, and libraries freely put connection strings, SQL,
file paths and input values into them. A handler that serialises "whatever
went wrong" into the response turns every unhandled exception into an
information leak. An attacker only needs to find a request that fails, for
example by sending odd input or waiting for a dependency to be slow.

This differs from secrets in request logs (problem 035), where the leak
went to an internal log store. Here it went straight to the internet.

## Solution
`safe_handle` separates what the client sees from what engineers see:

- **Unexpected exceptions** return 500 with a fixed message and a random
  `error_id` (16 hex characters from `secrets.token_hex`). The full
  traceback goes to the server-side log under the same id. Support can find
  the details from the id a customer quotes, and the response contains no
  password, hostname, file path or the word "Traceback".
- **Deliberate client errors** are raised as `ClientError` with a message
  written for the client, and are returned as 400 with that message. Only
  this class is trusted: a `ValueError` from a library is treated like any
  other unexpected error, because its message may contain internal data.

## Trade-offs
- **Harder debugging for API clients.** They get an id instead of a reason.
  Make the id easy to search in logs, and return specific 4xx messages for
  everything that is the client's fault.
- **The log now holds the secret.** The traceback in the server log still
  contains the DSN. Redact secrets in logs (problem 035) and keep passwords
  out of exception messages by not building DSNs into error strings.
- **Framework debug modes** (Flask/Django `DEBUG=True`, verbose error pages
  in app servers) do the same thing. Enforce "debug off" in production with
  a startup check, not only a code review.
- A catch-all handler must not itself fail. If logging raises, still return
  the generic 500.

## Run
```bash
python -m unittest -v test_solution.py
```
