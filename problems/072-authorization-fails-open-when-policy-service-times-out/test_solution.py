import unittest

from solution import (DECISION_CACHE_TTL_S, OUTAGE_GRACE_S, FailClosedAuthorizer, PolicyUnavailable,
                      Request, naive_authorize)

EMPLOYEE_READ = Request("employee-7", "read", "doc-42")
CONTRACTOR_DOWNLOAD = Request("contractor-3", "download", "doc-42")
OUTAGE_REQUESTS = 1000


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakePolicyService:
    """Answers from a set of allowed requests; can be switched to time out or misbehave."""

    def __init__(self, allowed):
        self.allowed = set(allowed)
        self.down = False
        self.reply_override = None
        self.calls = 0

    def check(self, user, action, resource):
        self.calls += 1
        if self.down:
            raise PolicyUnavailable("timed out after 2s")
        if self.reply_override is not None:
            return self.reply_override
        return {"allow": (user, action, resource) in self.allowed}

    def revoke(self, request):
        self.allowed.discard((request.user, request.action, request.resource))


def as_tuple(request):
    return (request.user, request.action, request.resource)


def make_service():
    return FakePolicyService({as_tuple(EMPLOYEE_READ)})


def count_allowed(authorize, request, attempts=OUTAGE_REQUESTS):
    allowed = 0
    for _ in range(attempts):
        if authorize(request):
            allowed += 1
    return allowed


class ReproduceProblem(unittest.TestCase):
    def test_contractor_is_denied_while_the_service_is_up(self):
        self.assertFalse(naive_authorize(make_service(), CONTRACTOR_DOWNLOAD))

    def test_outage_allows_every_request_of_an_unauthorized_user(self):
        service = make_service()
        service.down = True
        allowed = count_allowed(lambda request: naive_authorize(service, request), CONTRACTOR_DOWNLOAD)
        self.assertEqual(allowed, OUTAGE_REQUESTS)

    def test_reply_without_allow_field_is_treated_as_allow(self):
        service = make_service()
        service.reply_override = {"error": "policy bundle not loaded"}
        self.assertTrue(naive_authorize(service, CONTRACTOR_DOWNLOAD))

    def test_string_false_is_treated_as_allow(self):
        service = make_service()
        service.reply_override = {"allow": "false"}
        self.assertTrue(naive_authorize(service, CONTRACTOR_DOWNLOAD))


class FixFailClosed(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.service = make_service()
        self.authorizer = FailClosedAuthorizer(self.service, self.clock)

    def test_allowed_request_is_allowed(self):
        self.assertTrue(self.authorizer.authorize(EMPLOYEE_READ))

    def test_unauthorized_user_is_denied_during_an_outage(self):
        self.service.down = True
        self.assertEqual(count_allowed(self.authorizer.authorize, CONTRACTOR_DOWNLOAD), 0)
        self.assertEqual(self.authorizer.denied_because_unavailable, OUTAGE_REQUESTS)

    def test_malformed_or_truthy_non_boolean_replies_deny(self):
        for reply in ({"error": "policy bundle not loaded"}, {"allow": "true"}, {"allow": "false"}, {"allow": 1}, None, []):
            with self.subTest(reply=reply):
                self.service.reply_override = reply
                self.assertFalse(self.authorizer.authorize(CONTRACTOR_DOWNLOAD))

    def test_recent_allow_is_reused_without_calling_the_service(self):
        self.authorizer.authorize(EMPLOYEE_READ)
        self.clock.advance(DECISION_CACHE_TTL_S - 1)
        self.authorizer.authorize(EMPLOYEE_READ)
        self.assertEqual(self.service.calls, 1)

    def test_allow_is_rechecked_after_the_cache_ttl(self):
        self.authorizer.authorize(EMPLOYEE_READ)
        self.service.revoke(EMPLOYEE_READ)
        self.clock.advance(DECISION_CACHE_TTL_S)
        self.assertFalse(self.authorizer.authorize(EMPLOYEE_READ))

    def test_recent_allow_keeps_working_through_a_short_outage(self):
        self.authorizer.authorize(EMPLOYEE_READ)
        self.service.down = True
        self.clock.advance(OUTAGE_GRACE_S)
        self.assertTrue(self.authorizer.authorize(EMPLOYEE_READ))

    def test_old_allow_is_not_honoured_after_the_grace_period(self):
        self.authorizer.authorize(EMPLOYEE_READ)
        self.service.down = True
        self.clock.advance(OUTAGE_GRACE_S + 1)
        self.assertFalse(self.authorizer.authorize(EMPLOYEE_READ))

    def test_explicit_deny_clears_the_cached_allow(self):
        self.authorizer.authorize(EMPLOYEE_READ)
        self.service.revoke(EMPLOYEE_READ)
        self.clock.advance(DECISION_CACHE_TTL_S)
        self.authorizer.authorize(EMPLOYEE_READ)
        self.service.down = True
        self.assertFalse(self.authorizer.authorize(EMPLOYEE_READ))

    def test_cached_allow_does_not_cover_a_different_action(self):
        self.authorizer.authorize(EMPLOYEE_READ)
        self.service.down = True
        self.assertFalse(self.authorizer.authorize(Request("employee-7", "delete", "doc-42")))


if __name__ == "__main__":
    unittest.main()
