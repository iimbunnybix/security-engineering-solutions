import hashlib
import unittest

from solution import InvalidHost, Outbox, Request, ResetService, naive_request_reset

VICTIM = "victim@mail.example"
OUR_HOST = "app.shop.example"
ATTACKER_HOST = "attacker.example"


def reset_request(**headers: str) -> Request:
    return Request(headers=headers, form={"email": VICTIM})


def make_service() -> tuple[ResetService, Outbox]:
    outbox = Outbox()
    service = ResetService(f"https://{OUR_HOST}", {OUR_HOST}, {VICTIM}, outbox)
    return service, outbox


class ReproduceProblem(unittest.TestCase):
    def setUp(self) -> None:
        self.outbox = Outbox()
        self.tokens: dict[str, str] = {}

    def test_spoofed_host_header_puts_attacker_domain_in_the_email(self) -> None:
        naive_request_reset(reset_request(Host=ATTACKER_HOST), {VICTIM}, self.tokens, self.outbox)
        self.assertIn(f"https://{ATTACKER_HOST}/reset-password?token=", self.outbox.sent[0].body)

    def test_spoofed_forwarded_host_wins_over_the_real_host(self) -> None:
        request = reset_request(Host=OUR_HOST, **{"X-Forwarded-Host": ATTACKER_HOST})
        naive_request_reset(request, {VICTIM}, self.tokens, self.outbox)
        self.assertIn(ATTACKER_HOST, self.outbox.sent[0].body)


class FixBuildsLinksFromConfiguration(unittest.TestCase):
    def test_link_uses_the_canonical_base_url(self) -> None:
        service, outbox = make_service()
        service.request_reset(reset_request(Host=OUR_HOST))
        self.assertTrue(outbox.sent[0].body.startswith(
            f"Reset your password: https://{OUR_HOST}/reset-password?token="))

    def test_token_in_the_email_matches_the_stored_hash(self) -> None:
        service, outbox = make_service()
        service.request_reset(reset_request(Host=OUR_HOST))
        token = outbox.sent[0].body.split("token=")[1]
        self.assertEqual(service.token_hashes[VICTIM], hashlib.sha256(token.encode()).hexdigest())

    def test_unknown_email_gets_same_reply_and_no_mail(self) -> None:
        service, outbox = make_service()
        known = service.request_reset(reset_request(Host=OUR_HOST))
        unknown = service.request_reset(Request({"Host": OUR_HOST}, {"email": "nobody@x.example"}))
        self.assertEqual(known, unknown)
        self.assertEqual(len(outbox.sent), 1)


class FixRejectsUnknownHosts(unittest.TestCase):
    def assert_rejected_without_mail(self, request: Request) -> None:
        service, outbox = make_service()
        with self.assertRaises(InvalidHost):
            service.request_reset(request)
        self.assertEqual(outbox.sent, [])

    def test_attacker_host_header_is_rejected(self) -> None:
        self.assert_rejected_without_mail(reset_request(Host=ATTACKER_HOST))

    def test_attacker_forwarded_host_is_rejected(self) -> None:
        self.assert_rejected_without_mail(
            reset_request(Host=OUR_HOST, **{"X-Forwarded-Host": ATTACKER_HOST}))

    def test_missing_host_header_is_rejected(self) -> None:
        self.assert_rejected_without_mail(reset_request())

    def test_lookalike_hosts_are_rejected(self) -> None:
        for host in (f"{OUR_HOST}.attacker.example", f"{OUR_HOST}:8443", f"evil{OUR_HOST}",
                     f"{OUR_HOST}@attacker.example"):
            with self.subTest(host=host):
                self.assert_rejected_without_mail(reset_request(Host=host))

    def test_host_comparison_ignores_case_and_default_port(self) -> None:
        service, outbox = make_service()
        service.request_reset(reset_request(host="APP.Shop.Example:443"))
        self.assertEqual(len(outbox.sent), 1)


class FixValidatesConfiguration(unittest.TestCase):
    def test_non_https_or_path_base_url_is_refused(self) -> None:
        for base_url in ("http://app.shop.example", "app.shop.example",
                         "https://app.shop.example/reset"):
            with self.subTest(base_url=base_url):
                with self.assertRaises(ValueError):
                    ResetService(base_url, {OUR_HOST}, set(), Outbox())


if __name__ == "__main__":
    unittest.main()
