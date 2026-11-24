# 072 · A revoked contractor downloaded confidential files while the policy service was timing out

## Problem
A document-management SaaS (about 3,000 business customers) checks every
API call against a central policy service: "may user U do action A on
document D?". During a bad deploy of the policy service, its replies timed
out for about 20 minutes. Nobody noticed from the outside: the product kept
working perfectly. A week later a customer's security team asked why a
contractor, removed from their workspace that morning, had downloaded 1,800
documents during exactly that window. The audit log showed every request
"authorized". The incident had to be disclosed to the customer, and all
decisions made during the outage were unknowable after the fact.

## Root cause
The authorization client **failed open** (`naive_authorize`):

- Any exception from the policy call (timeout, connection refused, 5xx) was
  caught and answered with `True`, a choice made earlier "so our outage
  doesn't block customers". It also unblocks every attacker, and nothing
  pages, because nothing fails.
- The reply was read with `bool(reply.get("allow", True))`, so a reply
  without the field (for example `{"error": "policy bundle not loaded"}`)
  counted as allowed, and so did the *string* `"false"`, which is truthy.

`ReproduceProblem` shows the contractor denied while the service is up, and
1000 of 1000 download attempts allowed once it is down.

## Solution
`FailClosedAuthorizer`:

1. **Only an explicit yes grants access**: `is_explicit_allow` requires a
   dict whose `allow` is exactly `True`. Missing fields, `"true"`, `"false"`,
   `1`, `None` and lists all deny.
2. **Errors deny.** A `PolicyUnavailable` leads to a denial and is counted in
   `denied_because_unavailable`, so the outage becomes visible (an alert on
   that counter) instead of silent. In the test, the contractor gets 0 of
   1000 attempts through.
3. **Bounded grace for real users.** A fresh allow is reused for 30 s
   without asking again, and during an outage a cached allow for the *same*
   (user, action, resource) is honoured for up to 120 s. Users mid-task keep
   working through a short blip; nobody gains access they did not recently
   have. An explicit deny removes the cached allow, so a revocation that
   reached the service is never undone by an older cache entry.

## Trade-offs
- Failing closed turns a policy-service outage into a product outage after
  the grace period. That is the right default for authorization; make the
  policy service highly available (replicas, local sidecar with the policy
  bundle, as OPA deployments do) rather than weakening the client.
- During an outage a revocation can be ignored for up to `OUTAGE_GRACE_S`
  (120 s) for requests that were allowed just before. Shorten it (or set it
  to 0) for destructive actions such as delete or admin changes.
- The cache is per process and in memory; with many API pods each one asks
  the service separately. A shared cache would cut load but adds another
  dependency that can fail.
- Some endpoints really are public (health checks, the login page); mark
  those explicitly as not needing authorization rather than letting errors
  decide.

## Run
```bash
python -m unittest -v test_solution.py
```
