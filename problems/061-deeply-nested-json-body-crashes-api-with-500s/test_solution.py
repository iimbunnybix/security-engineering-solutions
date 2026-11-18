import json
import unittest

from solution import (MAX_NESTING_DEPTH, TooDeeplyNested, handle_save_draft,
                      max_nesting_depth, naive_handle_save_draft, parse_limited_json)

ATTACK_DEPTH = 100_000
WALKER_CRASH_DEPTH = 5_000


def nested_arrays(depth: int) -> str:
    """A valid JSON array nested ``depth`` levels deep: [[[...]]]."""
    return "[" * depth + "]" * depth


def nested_objects(depth: int) -> str:
    """A valid JSON object nested ``depth`` levels deep: {"a":{"a":{}}}."""
    return '{"a":' * depth + "{}" + "}" * depth


class ReproduceProblem(unittest.TestCase):
    def test_unclosed_brackets_crash_the_parser_with_recursion_error(self):
        with self.assertRaises(RecursionError):
            naive_handle_save_draft("[" * ATTACK_DEPTH)

    def test_body_that_parses_still_crashes_the_recursive_sanitiser(self):
        with self.assertRaises(RecursionError):
            naive_handle_save_draft(nested_arrays(WALKER_CRASH_DEPTH))

    def test_attack_body_is_small_enough_to_pass_a_1mb_body_limit(self):
        self.assertLess(len("[" * ATTACK_DEPTH), 1_000_000)


class FixRejectsDeepNesting(unittest.TestCase):
    def test_unclosed_brackets_get_a_400(self):
        self.assertEqual(handle_save_draft("[" * ATTACK_DEPTH).status, 400)

    def test_deep_but_valid_json_gets_a_400(self):
        self.assertEqual(handle_save_draft(nested_arrays(WALKER_CRASH_DEPTH)).status, 400)

    def test_deep_objects_are_rejected_too(self):
        with self.assertRaises(TooDeeplyNested):
            parse_limited_json(nested_objects(MAX_NESTING_DEPTH + 1))

    def test_depth_exactly_at_the_limit_is_accepted(self):
        self.assertEqual(handle_save_draft(nested_arrays(MAX_NESTING_DEPTH)).status, 200)

    def test_one_level_over_the_limit_is_rejected(self):
        self.assertEqual(handle_save_draft(nested_arrays(MAX_NESTING_DEPTH + 1)).status, 400)

    def test_normal_draft_is_saved_and_sanitised(self):
        body = json.dumps({"title": "<b>Hi</b>", "tags": ["a", "b"]})
        response = handle_save_draft(body)
        self.assertEqual(response.status, 200)
        self.assertIn('"bHi/b"', response.body)

    def test_malformed_json_is_still_a_400(self):
        self.assertEqual(handle_save_draft('{"title": ').body, "invalid JSON")


class FixScannerIgnoresBracketsInStrings(unittest.TestCase):
    def test_brackets_inside_a_string_do_not_count(self):
        body = json.dumps({"note": "[" * 1000})
        self.assertEqual(max_nesting_depth(body, MAX_NESTING_DEPTH), 1)
        self.assertEqual(handle_save_draft(body).status, 200)

    def test_escaped_quote_does_not_end_the_string_early(self):
        body = json.dumps({"note": 'say \\" [[[[ "'})
        self.assertEqual(max_nesting_depth(body, MAX_NESTING_DEPTH), 1)

    def test_scan_stops_early_once_over_the_limit(self):
        # The result is limit + 1, not the full 100,000: the loop returned early.
        self.assertEqual(max_nesting_depth("[" * ATTACK_DEPTH, 5), 6)


if __name__ == "__main__":
    unittest.main()
