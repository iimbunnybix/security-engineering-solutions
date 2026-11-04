import unittest

from solution import (AccessAudit, Invoice, InvoiceRepository, Principal,
                      get_invoice, get_invoice_vulnerable)


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


ALICE = Principal("alice", "acme", "member")
ALICE_BOSS = Principal("carol", "acme", "billing_admin")
MALLORY = Principal("mallory", "globex", "member")
SUPPORT = Principal("sam", "vendor", "support")


def build_repo():
    repo = InvoiceRepository()
    n = 10_000
    for tenant, owner in (("acme", "alice"), ("acme", "bob"), ("globex", "mallory")):
        for _ in range(50):
            n += 1
            repo.add(Invoice(n, tenant, owner, 1000 + n))
    return repo


ALICE_INV, BOB_INV, MALLORY_INV = 10_001, 10_051, 10_101


class ReproduceIdor(unittest.TestCase):
    def test_incrementing_id_leaks_other_tenants_invoices(self):
        repo = build_repo()
        leaked = [i for i in range(10_001, 10_151)
                  if (r := get_invoice_vulnerable(repo, MALLORY, i)).status == 200
                  and r.body.tenant_id != "globex"]
        self.assertEqual(len(leaked), 100)        # every acme invoice


class ObjectLevelAuthz(unittest.TestCase):
    def setUp(self):
        self.repo = build_repo()
        self.clock = FakeClock()
        self.audit = AccessAudit(threshold=20, window_s=60, clock=self.clock)

    def get(self, p, i):
        return get_invoice(self.repo, self.audit, p, i)

    def test_owner_can_read_own_invoice(self):
        r = self.get(ALICE, ALICE_INV)
        self.assertEqual((r.status, r.body.owner_id), (200, "alice"))

    def test_member_cannot_read_coworkers_invoice(self):
        self.assertEqual(self.get(ALICE, BOB_INV).status, 404)

    def test_billing_admin_reads_whole_tenant_only(self):
        self.assertEqual(self.get(ALICE_BOSS, BOB_INV).status, 200)
        self.assertEqual(self.get(ALICE_BOSS, MALLORY_INV).status, 404)

    def test_cross_tenant_and_missing_look_identical(self):
        foreign = self.get(MALLORY, ALICE_INV)
        missing = self.get(MALLORY, 99_999_999)
        self.assertEqual((foreign.status, foreign.body), (missing.status, missing.body))

    def test_support_denied_by_default(self):
        self.assertEqual(self.get(SUPPORT, ALICE_INV).status, 404)

    def test_unknown_role_denied(self):
        self.assertEqual(self.get(Principal("x", "acme", "auditor"), ALICE_INV).status, 404)

    def test_unauthenticated(self):
        self.assertEqual(self.get(None, ALICE_INV).status, 401)

    def test_enumeration_script_gets_nothing_and_is_blocked(self):
        statuses = [self.get(MALLORY, i).status for i in range(10_001, 10_101)]
        self.assertNotIn(200, statuses)
        self.assertEqual(statuses.count(404), 20)          # then blocked
        self.assertEqual(statuses.count(429), 80)
        self.assertEqual(len(self.audit.log), 20)
        self.assertEqual(self.audit.log[0]["object"], 10_001)
        # Blocked even for her own invoices until someone reviews it.
        self.assertEqual(self.get(MALLORY, MALLORY_INV).status, 429)

    def test_occasional_typos_do_not_trigger_block(self):
        for _ in range(10):
            self.get(ALICE, BOB_INV)
            self.clock.t += 10                              # spread over time
        self.assertFalse(self.audit.is_blocked(ALICE))
        self.assertEqual(self.get(ALICE, ALICE_INV).status, 200)

    def test_window_boundary(self):
        for _ in range(19):
            self.get(ALICE, BOB_INV)
        self.clock.t = 60                                   # first 19 fall out
        self.get(ALICE, BOB_INV)
        self.assertFalse(self.audit.is_blocked(ALICE))


if __name__ == "__main__":
    unittest.main()
