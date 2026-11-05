# 035 · Customers' login passwords and bearer tokens were readable by anyone with access to the log search tool

## Problem
A personal-finance app's API (about 600,000 monthly users) ships its
application logs to a third-party log search service, where around 150
engineers, contractors and the vendor's support staff can search 30 days of
history. During a routine access review, a contractor showed that searching
for `password` returned customers' login requests with the password in
clear text, and that `Authorization: Bearer …` headers and
`?access_token=…` statement-download links were in the logs too. Anyone with
log access could have logged in as any customer who had signed in during the
retention window. The company revoked every session and API token, forced a
password reset for every account that logged in during those 30 days, asked
the vendor to purge the index, and reported the incident to its regulator.

## Root cause
**Sensitive data written to logs (CWE-532).** A request-logging middleware
called `logger.info("request %s", request)` on the whole request object
(`log_request_naive`). Its `repr` contained the JSON body, all headers
(`Authorization`, `X-Api-Key`, `Cookie`) and the full URL with its query
string. The log line was correct for debugging and nobody looked at what it
contained.

The hot-fix (`log_request_hotfix`) popped the top-level `password` key from
the body before logging. It missed `profile.new_password` in nested bodies,
other key spellings, every header and the token in the query string. The
tests show the naive version leaking all six fake secrets and the hot-fix
still leaking five of the six.

Logs are a second copy of the data with weaker access control, longer
retention and more readers than the database, so a secret that reaches them
has effectively been shared with everyone who can search them.

## Solution
Two layers in `solution.py`:

1. **Allowlist what a request log contains** (`safe_request_summary`):
   method, URL with sensitive query values replaced, user id, a short list of
   safe headers (`user-agent`, `content-type`, `x-request-id`) and the body's
   *key names* only. Nothing new that a client sends can reach the log by
   accident, because new fields are dropped by default.
2. **A `RedactingFilter` on the log handler** as a safety net for every other
   log line, including third-party libraries. It redacts:
   - dict keys whose normalised name contains `password`, `secret`, `token`,
     `authorization`, `apikey`, `cookie` or `session` (so `X-Api-Key`,
     `apiKey`, `refreshToken` and `new_password` all match), recursively
     through dicts, lists, tuples and dataclasses;
   - secrets recognisable by shape in free text: `Bearer …` / `Basic …`
     credentials and `password=…`, `token=…`, `access_token=…` style
     assignments in messages and URLs;
   - exception tracebacks, which often include the failing value: the filter
     formats the traceback itself, redacts it and stores it in `exc_text`,
     which `logging.Formatter` reuses.

With the filter attached, even the original naive middleware no longer leaks
any of the fake secrets, and non-secret values (`Pune`, `u-42`) are still
logged. The filter returns a redacted copy and never modifies the caller's
objects.

## Trade-offs
- **Pattern-based redaction is a safety net, not a guarantee.** A secret
  under an innocent key (`{"note": "<password>"}`) or in a format the
  patterns do not know is not caught. That is why the allowlist is the main
  layer; the filter catches mistakes elsewhere.
- **Over-redaction.** Substring matching redacts harmless keys such as
  `session_count` or `token_expiry`. Losing a debugging value is cheaper than
  leaking a credential; add an explicit exception list if one matters.
- **Cost.** Redacting every record walks its arguments and runs two regexes.
  That is small next to formatting and shipping the line, but noticeable at
  very high log volume; the allowlisted summary is cheaper than logging the
  whole request.
- **Already-leaked data must still be cleaned up**: rotate exposed
  credentials, purge the log index and any archives, and check backups of
  the log store. Prevention also needs log access control and short
  retention.
- Short-lived tokens and moving tokens out of URLs (headers or POST bodies
  instead of `?access_token=`) shrink what a future leak exposes; URLs also
  end up in proxy logs and browser history that this filter never sees.

## Run
```bash
python -m unittest -v test_solution.py
```
