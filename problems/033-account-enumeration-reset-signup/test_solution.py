import unittest

from solution import (GENERIC_RESET_REPLY, GENERIC_SIGNUP_REPLY, INVALID_EMAIL_REPLY,
                      WEAK_PASSWORD_REPLY, Account, AccountEndpoints, EmailOutbox,
                      NaiveAccountEndpoints, normalize_email)

SMTP_SEND_SECONDS = 0.400        # modelled latency of one synchronous SMTP send
PASSWORD_HASH_SECONDS = 0.250    # modelled cost of one slow password hash
GOOD_PASSWORD = "correct-horse-battery"
REGISTERED = ["alice@example.test", "bob@example.test", "chen@example.test"]
UNREGISTERED = ["dana@example.test", "erik@example.test", "fatima@example.test"]


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeHasher:
    """Costs PASSWORD_HASH_SECONDS of fake time per call."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.calls = 0

    def hash(self, password: str) -> str:
        self.clock.advance(PASSWORD_HASH_SECONDS)
        self.calls += 1
        return f"fake-hash-{self.calls}"


class FakeMailer:
    """Costs SMTP_SEND_SECONDS of fake time per email and records what was sent."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.sent: list[tuple[str, str, dict]] = []

    def send(self, to: str, template: str, data: dict) -> None:
        self.clock.advance(SMTP_SEND_SECONDS)
        self.sent.append((to, template, data))


def make_users() -> dict[str, Account]:
    return {email: Account(email, "existing-hash", verified=True) for email in REGISTERED}


def timed(clock: FakeClock, call) -> tuple[int, str, float]:
    """Run ``call`` and return (status, body, fake seconds it took)."""
    start = clock.now
    status, body = call()
    return status, body, round(clock.now - start, 6)


def fingerprint(email: str, status: int, body: str, seconds: float) -> tuple:
    """What an attacker compares: status, body (with the echoed email removed) and latency."""
    return status, body.replace(email, "<email>"), seconds


def guess_registered(observations: dict[str, tuple], known_registered: str) -> set[str]:
    """Attacker: emails whose fingerprint matches that of one address known to be registered."""
    reference = observations[known_registered]
    return {email for email, seen in observations.items() if seen == reference}


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.mailer = FakeMailer(self.clock)
        self.naive = NaiveAccountEndpoints(make_users(), FakeHasher(self.clock), self.mailer)

    def observe(self, call_for_email) -> dict[str, tuple]:
        observations = {}
        for email in REGISTERED + UNREGISTERED:
            status, body, seconds = timed(self.clock, lambda: call_for_email(email))
            observations[email] = fingerprint(email, status, body, seconds)
        return observations

    def test_forgot_password_message_reveals_registered_emails(self):
        observations = self.observe(self.naive.forgot_password)
        self.assertEqual(guess_registered(observations, REGISTERED[0]), set(REGISTERED))

    def test_forgot_password_timing_alone_reveals_registered_emails(self):
        observations = self.observe(self.naive.forgot_password)
        latencies = {email: seen[2] for email, seen in observations.items()}
        slow = {email for email, seconds in latencies.items() if seconds >= SMTP_SEND_SECONDS}
        self.assertEqual(slow, set(REGISTERED))

    def test_signup_conflict_reveals_registered_emails(self):
        observations = self.observe(lambda email: self.naive.signup(email, GOOD_PASSWORD))
        statuses = {email: seen[0] for email, seen in observations.items()}
        self.assertEqual({e for e, s in statuses.items() if s == 409}, set(REGISTERED))
        self.assertEqual(observations[REGISTERED[0]][2], 0.0)
        self.assertEqual(observations[UNREGISTERED[0]][2], PASSWORD_HASH_SECONDS + SMTP_SEND_SECONDS)


class FixUniformResponses(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.hasher = FakeHasher(self.clock)
        self.outbox = EmailOutbox()
        self.mailer = FakeMailer(self.clock)
        self.users = make_users()
        self.endpoints = AccountEndpoints(self.users, self.hasher, self.outbox)

    def observe(self, call_for_email) -> dict[str, tuple]:
        observations = {}
        for email in REGISTERED + UNREGISTERED:
            status, body, seconds = timed(self.clock, lambda: call_for_email(email))
            observations[email] = fingerprint(email, status, body, seconds)
        return observations

    def test_forgot_password_looks_identical_for_every_email(self):
        observations = self.observe(self.endpoints.forgot_password)
        self.assertEqual(set(observations.values()), {(202, GENERIC_RESET_REPLY, 0.0)})

    def test_signup_looks_identical_for_every_email(self):
        observations = self.observe(lambda email: self.endpoints.signup(email, GOOD_PASSWORD))
        self.assertEqual(set(observations.values()),
                         {(202, GENERIC_SIGNUP_REPLY, PASSWORD_HASH_SECONDS)})

    def test_attacker_guess_matches_every_address(self):
        observations = self.observe(self.endpoints.forgot_password)
        guessed = guess_registered(observations, REGISTERED[0])
        self.assertEqual(guessed, set(REGISTERED + UNREGISTERED))     # no information

    def test_registered_user_receives_a_working_reset_link(self):
        self.endpoints.forgot_password("  Alice@Example.TEST ")
        self.outbox.deliver_all(self.mailer)
        to, template, data = self.mailer.sent[0]
        self.assertEqual((to, template), ("alice@example.test", "password_reset"))
        self.assertEqual(self.endpoints.email_for_reset_token(data["token"]), "alice@example.test")

    def test_unregistered_address_gets_a_no_account_email_not_a_token(self):
        self.endpoints.forgot_password("dana@example.test")
        self.assertEqual([(m.to, m.template, m.data) for m in self.outbox.pending],
                         [("dana@example.test", "reset_no_account", {})])
        self.assertEqual(self.endpoints.reset_tokens, {})

    def test_email_delivery_happens_outside_the_request(self):
        self.endpoints.forgot_password("alice@example.test")
        self.assertEqual(self.mailer.sent, [])
        self.assertEqual(self.outbox.deliver_all(self.mailer), 1)

    def test_signup_with_existing_email_does_not_change_the_account(self):
        self.endpoints.signup("bob@example.test", "attacker-chosen-password")
        self.assertEqual(self.users["bob@example.test"].password_hash, "existing-hash")
        self.assertEqual(self.outbox.pending[0].template, "signup_existing_account")

    def test_signup_with_new_email_creates_unverified_account(self):
        self.endpoints.signup("dana@example.test", GOOD_PASSWORD)
        self.assertFalse(self.users["dana@example.test"].verified)
        self.assertEqual(self.outbox.pending[0].template, "verify_email")
        self.assertIn("token", self.outbox.pending[0].data)

    def test_tokens_are_stored_only_as_digests(self):
        self.endpoints.forgot_password("alice@example.test")
        token = self.outbox.pending[0].data["token"]
        self.assertNotIn(token, self.endpoints.reset_tokens)
        self.assertEqual(len(self.endpoints.reset_tokens), 1)

    def test_invalid_email_is_rejected_the_same_way_for_everyone(self):
        for raw in ("", "no-at-sign", "a@b@example.test", "x@localhost", "a b@example.test",
                    "@example.test", "x@" + "d" * 250 + ".test"):
            self.assertEqual(self.endpoints.forgot_password(raw), (400, INVALID_EMAIL_REPLY), raw)
        self.assertEqual(self.outbox.pending, [])

    def test_weak_password_is_rejected_before_any_lookup(self):
        for email in (REGISTERED[0], UNREGISTERED[0]):
            self.assertEqual(self.endpoints.signup(email, "short"), (400, WEAK_PASSWORD_REPLY))
        self.assertEqual(self.hasher.calls, 0)

    def test_normalization_trims_and_lowercases(self):
        self.assertEqual(normalize_email("  Chen@Example.Test\n"), "chen@example.test")


if __name__ == "__main__":
    unittest.main()
