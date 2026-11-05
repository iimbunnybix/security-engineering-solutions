import os
import secrets
import tempfile
import unittest
from pathlib import Path

from solution import (Forbidden, download_blocklist, download_safe, download_vulnerable,
                      handle_download, safe_resolve)


class Layout:
    """/tmp/x/app/config/app.env (secret), /tmp/x/app/exports/<tenant>/..."""

    def __init__(self, root: Path):
        self.app = root / "app"
        self.exports = self.app / "exports"
        (self.app / "config").mkdir(parents=True)
        self.secret = "DB_PASSWORD=" + secrets.token_urlsafe(12)   # fake, built at runtime
        (self.app / "config" / "app.env").write_text(self.secret)
        for tenant in ("acme", "globex"):
            d = self.exports / tenant / "2026"
            d.mkdir(parents=True)
            (d / "orders-10.csv").write_text(f"{tenant} orders\n")
        (self.exports / "acme" / "summary.csv").write_text("acme summary\n")


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.lay = Layout(Path(self._tmp.name))

    def tearDown(self):
        self._tmp.cleanup()


class ReproduceTraversal(Base):
    def test_dot_dot_reads_config_secret(self):
        base = str(self.lay.exports / "acme")
        data = download_vulnerable(base, "../../config/app.env")
        self.assertEqual(data.decode(), self.lay.secret)

    def test_absolute_path_discards_base(self):
        base = str(self.lay.exports / "acme")
        target = str(self.lay.app / "config" / "app.env")
        self.assertEqual(download_vulnerable(base, target).decode(), self.lay.secret)

    def test_double_encoding_survives_framework_decode(self):
        base = str(self.lay.exports / "acme")
        # Client sent %252e%252e%252f...; the framework decoded once to %2e%2e%2f...
        name = "%2e%2e%2f%2e%2e%2fconfig%2fapp.env"
        self.assertEqual(download_vulnerable(base, name).decode(), self.lay.secret)

    def test_blocklist_fix_is_bypassed(self):
        base = str(self.lay.exports / "acme")
        data = download_blocklist(base, "....//....//config/app.env")
        self.assertEqual(data.decode(), self.lay.secret)

    def test_other_tenant_readable(self):
        base = str(self.lay.exports / "acme")
        self.assertEqual(download_vulnerable(base, "../globex/2026/orders-10.csv"),
                         b"globex orders\n")


class SafeDownload(Base):
    ATTACKS = [
        "../../config/app.env",
        "2026/../../../config/app.env",
        "....//....//config/app.env",
        "%2e%2e%2f%2e%2e%2fconfig%2fapp.env",
        "../globex/2026/orders-10.csv",
        "..\\..\\config\\app.env",
        "summary.csv\x00.png",
        "./summary.csv",
        "2026//orders-10.csv",
        "",
        "a" * 300,
    ]

    def test_all_attacks_rejected_as_404(self):
        attacks = self.ATTACKS + [str(self.lay.app / "config" / "app.env")]
        for name in attacks:
            status, body = handle_download(self.lay.exports, "acme", name)
            self.assertEqual((status, body), (404, b"not found"), repr(name))

    def test_legitimate_files(self):
        self.assertEqual(handle_download(self.lay.exports, "acme", "summary.csv"),
                         (200, b"acme summary\n"))
        self.assertEqual(handle_download(self.lay.exports, "acme", "2026/orders-10.csv"),
                         (200, b"acme orders\n"))

    def test_symlink_escape_rejected(self):
        link = self.lay.exports / "acme" / "innocent.csv"
        os.symlink(self.lay.app / "config" / "app.env", link)
        self.assertEqual(download_vulnerable(str(self.lay.exports / "acme"), "innocent.csv").decode(),
                         self.lay.secret)
        with self.assertRaisesRegex(Forbidden, "outside tenant"):
            safe_resolve(self.lay.exports, "acme", "innocent.csv")

    def test_symlink_inside_tenant_allowed(self):
        link = self.lay.exports / "acme" / "latest.csv"
        os.symlink(self.lay.exports / "acme" / "2026" / "orders-10.csv", link)
        self.assertEqual(download_safe(self.lay.exports, "acme", "latest.csv"), b"acme orders\n")

    def test_hard_link_to_config_secret_is_rejected(self):
        # A hard link has no target to resolve, so the containment check passes.
        link = self.lay.exports / "acme" / "report.csv"
        os.link(self.lay.app / "config" / "app.env", link)
        self.assertEqual(download_vulnerable(str(self.lay.exports / "acme"), "report.csv").decode(),
                         self.lay.secret)
        with self.assertRaisesRegex(Forbidden, "hard link"):
            download_safe(self.lay.exports, "acme", "report.csv")
        self.assertEqual(handle_download(self.lay.exports, "acme", "report.csv"),
                         (404, b"not found"))

    def test_symlink_loop_raises_forbidden(self):
        # Python 3.13+ raises OSError(ELOOP) here, 3.10-3.12 raise RuntimeError.
        acme = self.lay.exports / "acme"
        os.symlink(acme / "loop2", acme / "loop1")
        os.symlink(acme / "loop1", acme / "loop2")
        with self.assertRaises(Forbidden):
            safe_resolve(self.lay.exports, "acme", "loop1")
        self.assertEqual(handle_download(self.lay.exports, "acme", "loop1"), (404, b"not found"))

    def test_unknown_tenant_raises_forbidden_not_oserror(self):
        with self.assertRaises(Forbidden):
            safe_resolve(self.lay.exports, "initech", "summary.csv")

    def test_directory_and_missing_rejected(self):
        for name in ("2026", "nope.csv"):
            self.assertEqual(handle_download(self.lay.exports, "acme", name)[0], 404)

    def test_tenant_id_cannot_traverse(self):
        for tenant in ("..", "acme/..", "acme/../globex"):
            self.assertEqual(handle_download(self.lay.exports, tenant, "summary.csv")[0], 404)

    def test_unknown_tenant(self):
        self.assertEqual(handle_download(self.lay.exports, "initech", "summary.csv")[0], 404)


if __name__ == "__main__":
    unittest.main()
