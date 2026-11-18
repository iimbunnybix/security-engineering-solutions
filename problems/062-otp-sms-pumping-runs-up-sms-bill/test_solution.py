import unittest

from solution import (GLOBAL_HOURLY_LIMIT, PER_NUMBER_HOURLY_LIMIT, PER_PREFIX_HOURLY_LIMIT,
                      WINDOW_SECONDS, NaiveOtpSender, OtpSender, SmsGateway)

PUMPED_NUMBERS = 1000


class FakeClock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def pumped_block(count: int) -> list[str]:
    """Consecutive numbers in one range, as an SMS-pumping bot sends them."""
    return [f"+91982000{index:04d}" for index in range(count)]


def spread_out_users(count: int) -> list[str]:
    """Real users: each in a different number range."""
    return [f"+91{70000 + index * 37:05d}{index:05d}" for index in range(count)]


def pump(sender, numbers: list[str], attempts_per_number: int) -> None:
    for _ in range(attempts_per_number):
        for phone in numbers:
            sender.request_code(phone)


class ReproduceProblem(unittest.TestCase):
    def test_bot_pays_out_three_sms_per_number_in_one_hour(self):
        gateway = SmsGateway()
        pump(NaiveOtpSender(gateway, FakeClock()), pumped_block(PUMPED_NUMBERS), 5)
        self.assertEqual(len(gateway.sent), PUMPED_NUMBERS * PER_NUMBER_HOURLY_LIMIT)

    def test_foreign_premium_numbers_are_sent_too(self):
        gateway = SmsGateway()
        NaiveOtpSender(gateway, FakeClock()).request_code("+88200000001")
        self.assertEqual(len(gateway.sent), 1)


class FixLimitsMatchTheAttack(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()
        self.gateway = SmsGateway()
        self.sender = OtpSender(self.gateway, self.clock)

    def test_pumped_range_is_capped_at_the_range_limit(self):
        pump(self.sender, pumped_block(PUMPED_NUMBERS), 5)
        self.assertEqual(len(self.gateway.sent), PER_PREFIX_HOURLY_LIMIT)

    def test_country_we_do_not_serve_is_never_sent(self):
        self.assertFalse(self.sender.request_code("+88200000001"))
        self.assertEqual(self.sender.rejection_reason("+88200000001"), "country not served")

    def test_malformed_number_is_rejected(self):
        for phone in ("919820012345", "+91 98200 12345", "+91٩٨٢٠٠١٢٣٤٥", "+1234"):
            with self.subTest(phone=phone):
                self.assertEqual(self.sender.rejection_reason(phone), "invalid number")

    def test_one_number_still_gets_only_three_codes(self):
        for _ in range(5):
            self.sender.request_code("+919820012345")
        self.assertEqual(len(self.gateway.sent), PER_NUMBER_HOURLY_LIMIT)

    def test_real_users_in_different_ranges_all_get_codes(self):
        users = spread_out_users(100)
        pump(self.sender, users, 1)
        self.assertEqual(len(self.gateway.sent), 100)

    def test_global_budget_caps_a_bot_spread_over_many_ranges(self):
        pump(self.sender, spread_out_users(GLOBAL_HOURLY_LIMIT + 100), 1)
        self.assertEqual(len(self.gateway.sent), GLOBAL_HOURLY_LIMIT)
        self.assertEqual(self.sender.rejection_reason("+919999912345"), "global budget")

    def test_range_opens_again_after_the_window_passes(self):
        pump(self.sender, pumped_block(PER_PREFIX_HOURLY_LIMIT), 1)
        self.assertFalse(self.sender.request_code("+919820009999"))
        self.clock.advance(WINDOW_SECONDS)
        self.assertTrue(self.sender.request_code("+919820009999"))

    def test_rejected_requests_do_not_use_up_any_limit(self):
        for _ in range(GLOBAL_HOURLY_LIMIT * 2):
            self.sender.request_code("+88200000001")
        self.assertTrue(self.sender.request_code("+919820012345"))


if __name__ == "__main__":
    unittest.main()
