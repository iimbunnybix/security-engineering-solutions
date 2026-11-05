import random
import secrets
import unittest

from solution import (BadRequest, SearchParams, blind_extract, create_db, handle_search,
                      search_safe, search_vulnerable)

HEX = "0123456789abcdef"
TARGET = "SELECT token_hash FROM users WHERE id = 1"


def make_db():
    rng = random.Random(9)
    words = ["anchor", "basket", "candle", "drill", "easel", "funnel", "glove", "hammer"]
    rows = [(f"{w}-{i}", round(rng.uniform(1, 500), 2), "tools", f"2026-0{1 + i % 9}-01")
            for i, w in enumerate(words)]
    rows += [("other", 9.99, "garden", "2026-01-01")]
    fake_hash = secrets.token_hex(16)          # generated at runtime, never a literal
    conn = create_db(rows, [("admin@example.test", fake_hash)])
    return conn, fake_hash


class ReproduceInjection(unittest.TestCase):
    def test_sort_parameter_leaks_admin_token_hash(self):
        conn, fake_hash = make_db()
        stolen, requests = blind_extract(
            lambda sort: search_vulnerable(conn, "tools", sort=sort), TARGET, 32, HEX)
        self.assertEqual(stolen, fake_hash)
        self.assertLessEqual(requests, 2 + 32 * 16)   # at most 514 ordinary-looking requests

    def test_direction_parameter_is_injectable_too(self):
        conn, fake_hash = make_db()
        # A constant first sort key, then the attacker's expression after a comma.
        stolen, _ = blind_extract(
            lambda expr: search_vulnerable(conn, "tools", sort="0+0", direction=", " + expr),
            TARGET, 32, HEX)
        self.assertEqual(stolen, fake_hash)


class AllowlistFix(unittest.TestCase):
    def setUp(self):
        self.conn, self.fake_hash = make_db()

    def safe_search(self, sort):
        status, body = handle_search(self.conn, {"category": "tools", "sort": sort})
        if status != 200:
            raise BadRequest(body["error"])
        return body

    def test_extraction_fails(self):
        stolen, requests = blind_extract(self.safe_search, TARGET, 32, HEX)
        self.assertEqual(stolen, "")
        self.assertEqual(requests, 3)                 # first payload rejected with 400

    def test_rejects_unknown_sort_and_direction(self):
        for q in ({"sort": "price; DROP TABLE users"}, {"sort": "(SELECT 1)"},
                  {"dir": "asc, (SELECT token_hash FROM users)"}, {"sort": "id"}):
            status, body = handle_search(self.conn, {"category": "tools", **q})
            self.assertEqual(status, 400, q)
            self.assertNotIn("token_hash", str(body))

    def test_limit_validation(self):
        for limit in ("0", "101", "-1", "10 OR 1=1", "1e3", ""):
            status, _ = handle_search(self.conn, {"category": "tools", "limit": limit})
            self.assertEqual(status, 400, limit)

    def test_non_ascii_digit_limits_are_rejected_with_400(self):
        for limit in ("\u00b2", "\u00b9\u2070", "\u0661\u0660"):   # superscripts, Arabic-Indic "10"
            status, body = handle_search(self.conn, {"category": "tools", "limit": limit})
            self.assertEqual(status, 400, ascii(limit))
            self.assertIn("error", body)

    def test_category_value_is_bound(self):
        status, body = handle_search(self.conn, {"category": "tools' OR '1'='1"})
        self.assertEqual((status, body), (200, []))
        status, body = handle_search(self.conn, {"category": "garden"})
        self.assertEqual(body, [9])

    def test_legitimate_sorts_work(self):
        by_price = search_safe(self.conn, SearchParams("tools", "price", "asc"))
        prices = [self.conn.execute("SELECT price FROM products WHERE id=?", (i,)).fetchone()[0]
                  for i in by_price]
        self.assertEqual(prices, sorted(prices))
        desc = search_safe(self.conn, SearchParams("tools", "price", "desc"))
        self.assertEqual(desc, by_price[::-1])

    def test_case_and_whitespace_normalised(self):
        self.assertEqual(SearchParams.parse({"category": "tools", "sort": " Price ", "dir": "DESC"}),
                         SearchParams("tools", "price", "desc", 20))

    def test_missing_category(self):
        self.assertEqual(handle_search(self.conn, {})[0], 400)


if __name__ == "__main__":
    unittest.main()
