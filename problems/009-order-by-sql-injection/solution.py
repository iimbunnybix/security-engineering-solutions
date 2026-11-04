"""Product search with a user-controlled sort order, without SQL injection.

SQL placeholders bind *values*, not identifiers or keywords, so the original
code formatted the ``sort`` and ``dir`` query parameters straight into the
``ORDER BY`` clause. Any SQL expression is valid there, including a
``CASE WHEN (SELECT ...) THEN price ELSE name END`` that makes the result order
reveal one bit of any table per request.

The fix maps public sort names to fixed SQL fragments (an allowlist), accepts
only ``asc``/``desc``, bounds ``limit`` and keeps every value bound as a
parameter.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass


def create_db(rows: list[tuple[str, float, str, str]], users: list[tuple[str, str]]) -> sqlite3.Connection:
    """In-memory database. ``rows``: (name, price, category, created_at); ``users``: (email, token_hash)."""
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL,
                               category TEXT, created_at TEXT);
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, token_hash TEXT);
    """)
    conn.executemany("INSERT INTO products (name, price, category, created_at) VALUES (?,?,?,?)", rows)
    conn.executemany("INSERT INTO users (email, token_hash) VALUES (?,?)", users)
    return conn


# ------------------------------------------------------------- vulnerable
def search_vulnerable(conn: sqlite3.Connection, category: str, sort: str = "name",
                      direction: str = "asc", limit: int = 20) -> list[int]:
    """Original endpoint: the category is bound, but sort/direction are formatted in."""
    sql = (f"SELECT id FROM products WHERE category = ? "
           f"ORDER BY {sort} {direction} LIMIT ?")
    return [r[0] for r in conn.execute(sql, (category, limit))]


# ------------------------------------------------------------------ fixed
class BadRequest(ValueError):
    """Maps to HTTP 400. The message is safe to show to the client."""


# Public sort key -> fixed SQL. Never derived from user input.
SORT_COLUMNS = {
    "name": "name",
    "price": "price",
    "newest": "created_at",
}
DIRECTIONS = {"asc": "ASC", "desc": "DESC"}
MAX_LIMIT = 100


@dataclass(frozen=True)
class SearchParams:
    category: str
    sort: str = "name"
    direction: str = "asc"
    limit: int = 20

    @classmethod
    def parse(cls, query: dict[str, str]) -> "SearchParams":
        """Validate raw query-string values. Raises BadRequest on anything unexpected."""
        category = query.get("category", "")
        if not category or len(category) > 64:
            raise BadRequest("category is required (max 64 chars)")
        sort = query.get("sort", "name").strip().lower()
        if sort not in SORT_COLUMNS:
            raise BadRequest(f"sort must be one of {sorted(SORT_COLUMNS)}")
        direction = query.get("dir", "asc").strip().lower()
        if direction not in DIRECTIONS:
            raise BadRequest("dir must be asc or desc")
        raw_limit = query.get("limit", "20")
        if not raw_limit.isdigit():
            raise BadRequest("limit must be a positive integer")
        limit = int(raw_limit)
        if not 1 <= limit <= MAX_LIMIT:
            raise BadRequest(f"limit must be between 1 and {MAX_LIMIT}")
        return cls(category, sort, direction, limit)


def search_safe(conn: sqlite3.Connection, params: SearchParams) -> list[int]:
    """Only constant SQL fragments are concatenated; all values are bound."""
    column = SORT_COLUMNS[params.sort]
    direction = DIRECTIONS[params.direction]
    # id as tie-breaker: stable order for equal prices/names (and stable paging)
    sql = (f"SELECT id FROM products WHERE category = ? "
           f"ORDER BY {column} {direction}, id {direction} LIMIT ?")
    return [r[0] for r in conn.execute(sql, (params.category, params.limit))]


def handle_search(conn: sqlite3.Connection, query: dict[str, str]) -> tuple[int, object]:
    """HTTP-style handler returning (status, body)."""
    try:
        params = SearchParams.parse(query)
    except BadRequest as exc:
        return 400, {"error": str(exc)}
    return 200, search_safe(conn, params)


# ------------------------------------------------- attacker's extraction
def blind_extract(search, target_sql: str, length: int, alphabet: str) -> tuple[str, int]:
    """Recover ``target_sql``'s value one character at a time via result ordering.

    ``search(sort_expr) -> list[int]``. Returns (value, requests made). Used by the
    tests to prove the vulnerability is exploitable and the fix is not.
    """
    by_price = search("price")
    by_name = search("name")
    if by_price == by_name:
        raise RuntimeError("oracle needs the two orderings to differ")
    value, requests = "", 2
    for i in range(1, length + 1):
        for ch in alphabet:
            expr = f"(CASE WHEN substr(({target_sql}),{i},1)='{ch}' THEN price ELSE name END)"
            requests += 1
            try:
                result = search(expr)
            except Exception:
                return value, requests
            if result == by_price:
                value += ch
                break
        else:
            break
    return value, requests
