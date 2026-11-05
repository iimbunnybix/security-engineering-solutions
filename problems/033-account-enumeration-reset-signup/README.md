# 033 · A spam crew knew exactly which leaked email addresses were real customers before sending them fake "your order is on hold" emails

## Problem
An online pharmacy with about 400,000 customer accounts saw a wave of very
convincing phishing emails ("your prescription order is on hold, log in to
confirm"). Every one went to a real customer; non-customers on the same
leaked mailing lists got nothing. The WAF logs showed why: in the week before,
a few hundred IPs had sent around 2 million requests to
`POST /password/forgot` and `POST /signup`, each with a different email from a
public breach list. No passwords were guessed and no account was entered, but
the site had told the attackers which addresses were customers, which made the
phishing far more effective and is itself a personal-data disclosure (being a
pharmacy customer is sensitive). The privacy team had to treat it as a
reportable incident.

## Root cause
**Account enumeration**: both endpoints behaved differently depending on
whether the email was registered (`NaiveAccountEndpoints`).

- **Different messages and status codes.** Forgot-password answered
  `404 "No account found for that email address."` or
  `200 "We have sent a reset link to …"`. Signup answered
  `409 "An account with this email already exists."` or `201`.
- **Different timing, even if the messages had matched.** The slow work only
  ran on one branch: forgot-password sent the email over SMTP inside the
  request for known addresses only, and signup hashed the password and sent a
  verification email for new addresses only. With the latencies modelled in
  the tests (SMTP send 400 ms, password hash 250 ms), forgot-password takes
  400 ms for a registered email and 0 ms for an unknown one, and signup takes
  0 ms for a registered email and 650 ms for a new one. A difference that size
  is visible in a single request over the internet.

The tests reproduce both leaks: comparing the response fingerprint (status,
body, latency) with that of one address the attacker knows is registered
separates the registered emails from the rest without error.

## Solution
`AccountEndpoints` in `solution.py`:

- **One response per endpoint.** Forgot-password always returns
  `202 "If an account exists for that address, we have emailed a reset link."`
  and signup always returns `202 "Check your inbox to finish creating your
  account."`. The body never echoes the email back.
- **The same work on both branches.** Signup hashes the submitted password
  *before* checking whether the email exists (the hash is thrown away for an
  existing account); both endpoints generate a token and queue **exactly one**
  email whatever the outcome. In the test model every forgot-password request
  takes 0 ms and every signup takes 250 ms, registered or not.
- **Email delivery leaves the request path.** Handlers only append to an
  outbox (`EmailOutbox`, in production one row inserted in the same
  transaction); a worker sends later. SMTP latency and failures can no longer
  show up in response times.
- **The truth goes to the mailbox, not the response.** A registered user
  gets the reset link; an unknown address gets "someone asked to reset a
  password, but there is no account for this email"; signing up with an
  existing email sends its owner "you already have an account, log in or
  reset your password" and never changes the existing account.
- **Validation depends only on the input.** Malformed emails and short
  passwords get a 400 before any lookup, so a 400 says nothing about
  accounts. Reset and verification tokens are 256-bit and stored as SHA-256
  digests.

## Trade-offs
- Equal *modelled* cost is not equal *real* latency: a database lookup that
  hits versus misses a cache, or an extra row insert, still differs by
  microseconds to milliseconds. Over many requests that can be measurable, so
  also rate-limit these endpoints per IP and per target email, and alert on
  volume. Padding responses to a fixed minimum duration is another option,
  but it costs worker time.
- UX gets a little worse: a user who mistypes their email no longer sees
  "no account found". The "no account" email covers the common case of
  someone who forgot which address they used.
- Sending emails to addresses that have no account can be abused to spam
  third parties through your mail server; per-recipient rate limits and a
  cap per IP are needed.
- Login must behave the same way (same error for unknown user and wrong
  password, dummy hash for unknown users; problem 001 does this), and so must
  any other endpoint that takes an email or username, such as "invite a
  teammate" or a public profile URL. One leaking endpoint is enough.
- Where the business needs to show "this email is taken" (e.g. picking a
  public username), accept the leak deliberately and protect it with CAPTCHA
  and strict rate limits.

## Run
```bash
python -m unittest -v test_solution.py
```
