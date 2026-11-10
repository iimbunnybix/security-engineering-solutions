import json
import secrets
import unittest

from solution import (NAIVE_DEDUP_RETENTION_SECONDS, TOLERANCE_SECONDS,
                      NaiveWebhookReceiver, Rejected, WebhookReceiver,
                      naive_sign, parse_signature_header, sign_delivery)

START_TIME = 1_700_000_000
DAY = 24 * 3600


class FakeClock:
    def __init__(self, now: float = START_TIME) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def payout_body(event_id: str = "evt_1001") -> str:
    return json.dumps({"id": event_id, "type": "payout.approved", "amount": 50000})


def fresh_secret() -> bytes:
    """Fake signing secret generated at runtime."""
    return secrets.token_bytes(32)


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.secret = fresh_secret()
        self.receiver = NaiveWebhookReceiver(self.secret, self.clock)
        self.body = payout_body()
        self.signature = naive_sign(self.secret, self.body)

    def test_first_delivery_is_processed(self):
        self.assertTrue(self.receiver.receive(self.body, self.signature))

    def test_immediate_replay_is_caught_by_dedup_table(self):
        self.receiver.receive(self.body, self.signature)
        self.assertFalse(self.receiver.receive(self.body, self.signature))

    def test_replay_after_dedup_retention_pays_again(self):
        self.receiver.receive(self.body, self.signature)
        self.clock.advance(NAIVE_DEDUP_RETENTION_SECONDS + 1)
        self.assertTrue(self.receiver.receive(self.body, self.signature))


class FixTimestampedSignatures(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.secret = fresh_secret()
        self.receiver = WebhookReceiver([self.secret], self.clock)
        self.body = payout_body()

    def header_now(self, secrets_list=None, offset: int = 0) -> str:
        return sign_delivery(secrets_list or [self.secret], self.body,
                             int(self.clock()) + offset)

    def test_fresh_valid_delivery_is_processed(self):
        self.assertEqual(self.receiver.receive(self.body, self.header_now()), "evt_1001")

    def test_replay_inside_window_is_rejected(self):
        header = self.header_now()
        self.receiver.receive(self.body, header)
        self.clock.advance(60)
        with self.assertRaisesRegex(Rejected, "replayed"):
            self.receiver.receive(self.body, header)

    def test_replay_after_window_is_rejected_by_timestamp(self):
        header = self.header_now()
        self.receiver.receive(self.body, header)
        self.clock.advance(8 * DAY)
        with self.assertRaisesRegex(Rejected, "tolerance"):
            self.receiver.receive(self.body, header)

    def test_replay_cache_is_small_after_window(self):
        self.receiver.receive(self.body, self.header_now())
        self.clock.advance(2 * TOLERANCE_SECONDS + 1)
        self.receiver.receive(payout_body("evt_2002"), sign_delivery(
            [self.secret], payout_body("evt_2002"), int(self.clock())))
        self.assertEqual(list(self.receiver.replay_cache), ["evt_2002"])

    def test_future_timestamp_beyond_tolerance_is_rejected(self):
        with self.assertRaisesRegex(Rejected, "tolerance"):
            self.receiver.receive(self.body, self.header_now(offset=TOLERANCE_SECONDS + 1))

    def test_future_timestamp_at_edge_cannot_be_replayed_later(self):
        header = self.header_now(offset=TOLERANCE_SECONDS)
        self.receiver.receive(self.body, header)
        self.clock.advance(2 * TOLERANCE_SECONDS)
        with self.assertRaises(Rejected):
            self.receiver.receive(self.body, header)

    def test_replay_on_last_fresh_second_is_still_caught(self):
        header = self.header_now()
        self.receiver.receive(self.body, header)
        self.clock.advance(TOLERANCE_SECONDS)
        with self.assertRaisesRegex(Rejected, "replayed"):
            self.receiver.receive(self.body, header)
        self.clock.advance(1)
        with self.assertRaisesRegex(Rejected, "tolerance"):
            self.receiver.receive(self.body, header)

    def test_replayed_provider_retry_is_rejected_after_first_entry_expires(self):
        self.receiver.receive(self.body, self.header_now())
        self.clock.advance(200)
        retry_header = self.header_now()
        with self.assertRaisesRegex(Rejected, "replayed"):
            self.receiver.receive(self.body, retry_header)
        # The first delivery's entry has expired, but the retry is still fresh.
        self.clock.advance(TOLERANCE_SECONDS - 200 + 1)
        with self.assertRaisesRegex(Rejected, "replayed"):
            self.receiver.receive(self.body, retry_header)

    def test_changing_the_timestamp_breaks_the_signature(self):
        header = self.header_now()
        signature = parse_signature_header(header)[1][0]
        forged = f"t={int(self.clock()) + 10},v1={signature}"
        with self.assertRaisesRegex(Rejected, "bad signature"):
            self.receiver.receive(self.body, forged)

    def test_tampered_body_is_rejected(self):
        header = self.header_now()
        with self.assertRaisesRegex(Rejected, "bad signature"):
            self.receiver.receive(payout_body("evt_9999"), header)

    def test_wrong_secret_is_rejected(self):
        with self.assertRaisesRegex(Rejected, "bad signature"):
            self.receiver.receive(self.body, self.header_now([fresh_secret()]))

    def test_malformed_headers_are_rejected(self):
        for header in ["", "t=abc,v1=00", "v1=00", f"t={START_TIME}", "garbage"]:
            with self.assertRaisesRegex(Rejected, "malformed"):
                self.receiver.receive(self.body, header)

    def test_unicode_digit_timestamp_is_rejected_not_crashing(self):
        with self.assertRaisesRegex(Rejected, "malformed"):
            self.receiver.receive(self.body, "t=\u00b2,v1=ab")

    def test_non_ascii_signature_is_rejected_not_crashing(self):
        header = f"t={int(self.clock())},v1=\u00e9"
        with self.assertRaisesRegex(Rejected, "bad signature"):
            self.receiver.receive(self.body, header)

    def test_body_without_event_id_is_rejected(self):
        body = json.dumps({"type": "payout.approved"})
        header = sign_delivery([self.secret], body, int(self.clock()))
        with self.assertRaisesRegex(Rejected, "event id"):
            self.receiver.receive(body, header)


class FixSecretRotation(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.old_secret = fresh_secret()
        self.new_secret = fresh_secret()
        self.body = payout_body()

    def test_receiver_on_old_secret_accepts_dual_signed_delivery(self):
        receiver = WebhookReceiver([self.old_secret], self.clock)
        header = sign_delivery([self.new_secret, self.old_secret], self.body, START_TIME)
        self.assertEqual(receiver.receive(self.body, header), "evt_1001")

    def test_receiver_accepting_both_secrets_works_before_sender_switches(self):
        receiver = WebhookReceiver([self.new_secret, self.old_secret], self.clock)
        header = sign_delivery([self.old_secret], self.body, START_TIME)
        self.assertEqual(receiver.receive(self.body, header), "evt_1001")

    def test_retired_secret_is_rejected(self):
        receiver = WebhookReceiver([self.new_secret], self.clock)
        header = sign_delivery([self.old_secret], self.body, START_TIME)
        with self.assertRaises(Rejected):
            receiver.receive(self.body, header)


if __name__ == "__main__":
    unittest.main()
