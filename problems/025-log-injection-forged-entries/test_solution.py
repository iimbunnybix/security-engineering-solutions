import unittest

from solution import MAX_VALUE_LENGTH, AuthLog, escape_value

TIMESTAMP = "2026-11-05T10:00:00Z"
FORGED_SUFFIX = f"\n{TIMESTAMP} INFO login_succeeded user=admin"


def fixed_clock():
    return TIMESTAMP


def make_log(escape):
    return AuthLog(clock=fixed_clock, escape=escape)


class ReproduceProblem(unittest.TestCase):
    def test_newline_in_username_forges_a_success_line(self):
        log = make_log(escape=False)
        log.login_failed("mallory" + FORGED_SUFFIX)
        self.assertEqual(log.lines()[1], f"{TIMESTAMP} INFO login_succeeded user=admin")

    def test_unicode_line_separator_also_splits_the_entry(self):
        log = make_log(escape=False)
        log.login_failed("mallory fake entry")
        self.assertEqual(len(log.lines()), 2)


class FixEscapesUntrustedValues(unittest.TestCase):
    def test_newline_attack_stays_on_one_line(self):
        log = make_log(escape=True)
        log.login_failed("mallory" + FORGED_SUFFIX)
        self.assertEqual(len(log.lines()), 1)
        self.assertIn('user="mallory\\n2026', log.lines()[0])

    def test_every_unicode_line_break_is_escaped(self):
        log = make_log(escape=True)
        log.login_failed("a\rb\u0085c d e\x0bf\x0cg")
        self.assertEqual(len(log.lines()), 1)

    def test_terminal_escape_sequence_is_made_visible(self):
        self.assertEqual(escape_value("\x1b[2Jadmin"), '"\\x1b[2Jadmin"')

    def test_quote_cannot_close_the_value_early(self):
        self.assertEqual(escape_value('bob" role="admin'), '"bob\\" role=\\"admin"')

    def test_backslash_is_escaped_so_escapes_cannot_be_faked(self):
        self.assertEqual(escape_value("a\\nb"), '"a\\\\nb"')

    def test_normal_username_is_logged_readably(self):
        log = make_log(escape=True)
        log.login_failed("alice")
        self.assertEqual(log.lines(), [f'{TIMESTAMP} WARN login_failed user="alice"'])

    def test_non_ascii_username_is_kept(self):
        self.assertEqual(escape_value("José"), '"José"')

    def test_very_long_value_is_truncated(self):
        escaped = escape_value("x" * 10_000)
        self.assertEqual(escaped, '"' + "x" * MAX_VALUE_LENGTH + '...(truncated)"')


if __name__ == "__main__":
    unittest.main()
