import unittest

from solution import Forbidden, can_read, naive_can_read, read_object

ACME_INVOICE = "tenants/acme/invoices/7.pdf"
LABS_PAYROLL = "tenants/acme-labs/payroll/2026-10.csv"


def make_store() -> dict[str, bytes]:
    return {ACME_INVOICE: b"acme invoice", LABS_PAYROLL: b"acme-labs salaries"}


class ReproduceProblem(unittest.TestCase):
    def test_tenant_reads_its_own_file(self):
        self.assertTrue(naive_can_read("acme", ACME_INVOICE))

    def test_acme_can_read_acme_labs_payroll(self):
        self.assertTrue(naive_can_read("acme", LABS_PAYROLL))

    def test_dot_dot_segment_escapes_the_tenant_folder(self):
        self.assertTrue(naive_can_read("acme", "tenants/acme/../acme-labs/payroll/2026-10.csv"))


class FixComparesWholeSegments(unittest.TestCase):
    def test_tenant_reads_its_own_file(self):
        self.assertEqual(read_object(make_store(), "acme", ACME_INVOICE), b"acme invoice")

    def test_other_tenant_with_longer_name_is_forbidden(self):
        with self.assertRaises(Forbidden):
            read_object(make_store(), "acme", LABS_PAYROLL)

    def test_longer_named_tenant_still_reads_its_own_files(self):
        self.assertTrue(can_read("acme-labs", LABS_PAYROLL))
        self.assertFalse(can_read("acme-labs", ACME_INVOICE))

    def test_dot_dot_segment_is_forbidden(self):
        self.assertFalse(can_read("acme", "tenants/acme/../acme-labs/payroll/2026-10.csv"))

    def test_single_dot_and_empty_segments_are_forbidden(self):
        self.assertFalse(can_read("acme", "tenants/acme/./invoices/7.pdf"))
        self.assertFalse(can_read("acme", "tenants/acme//invoices/7.pdf"))

    def test_backslash_and_nul_are_forbidden(self):
        self.assertFalse(can_read("acme", "tenants/acme\\..\\acme-labs/x"))
        self.assertFalse(can_read("acme", "tenants/acme/x\x00.pdf"))

    def test_tenant_folder_itself_is_not_readable(self):
        self.assertFalse(can_read("acme", "tenants/acme"))
        self.assertFalse(can_read("acme", "tenants/acme/"))

    def test_key_outside_the_tenants_root_is_forbidden(self):
        self.assertFalse(can_read("acme", "backups/acme/db.sql"))

    def test_missing_own_object_raises_key_error_not_forbidden(self):
        with self.assertRaises(KeyError):
            read_object(make_store(), "acme", "tenants/acme/missing.pdf")

    def test_overlong_key_is_forbidden(self):
        self.assertFalse(can_read("acme", "tenants/acme/" + "a" * 2000))

    def test_tenant_name_with_slash_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            can_read("acme/invoices", ACME_INVOICE)


if __name__ == "__main__":
    unittest.main()
