import unittest

from solution import AccountService, ImpersonationForbidden, Session, actions_by

CUSTOMER = "cust-1001"
AGENT = "staff-ravi"
TICKET = "SUP-4821"
ORIGINAL_ACCOUNT = "payout-original"
ATTACKER_ACCOUNT = "payout-attacker"


def service_with_customer() -> AccountService:
    return AccountService(payout_accounts={CUSTOMER: ORIGINAL_ACCOUNT})


class ReproduceProblem(unittest.TestCase):
    def test_agent_change_is_logged_as_the_customer(self):
        service = service_with_customer()
        session = service.original_impersonate(AGENT, CUSTOMER)
        service.original_change_payout(session, ATTACKER_ACCOUNT)
        entry = service.audit_log[-1]
        self.assertEqual(entry.actor_id, CUSTOMER)
        self.assertFalse(entry.impersonated)

    def test_investigator_finds_nothing_done_by_the_agent(self):
        service = service_with_customer()
        session = service.original_impersonate(AGENT, CUSTOMER)
        service.original_change_payout(session, ATTACKER_ACCOUNT)
        self.assertEqual(actions_by(service.audit_log, AGENT), [])

    def test_payout_can_be_redirected_while_impersonating(self):
        service = service_with_customer()
        session = service.original_impersonate(AGENT, CUSTOMER)
        service.original_change_payout(session, ATTACKER_ACCOUNT)
        self.assertEqual(service.payout_accounts[CUSTOMER], ATTACKER_ACCOUNT)


class FixRecordTheRealActor(unittest.TestCase):
    def test_impersonation_start_is_logged_with_the_ticket(self):
        service = service_with_customer()
        service.impersonate(AGENT, CUSTOMER, TICKET)
        entry = service.audit_log[0]
        self.assertEqual((entry.action, entry.actor_id, entry.subject_id),
                         ("impersonation_started", AGENT, CUSTOMER))
        self.assertEqual(entry.detail, "ticket=SUP-4821")

    def test_reads_during_impersonation_name_the_agent(self):
        service = service_with_customer()
        session = service.impersonate(AGENT, CUSTOMER, TICKET)
        service.view_orders(session)
        entry = service.audit_log[-1]
        self.assertEqual(entry.actor_id, AGENT)
        self.assertTrue(entry.impersonated)

    def test_payout_change_is_refused_while_impersonating(self):
        service = service_with_customer()
        session = service.impersonate(AGENT, CUSTOMER, TICKET)
        with self.assertRaises(ImpersonationForbidden):
            service.change_payout(session, ATTACKER_ACCOUNT)
        self.assertEqual(service.payout_accounts[CUSTOMER], ORIGINAL_ACCOUNT)

    def test_refused_attempt_is_in_the_audit_log(self):
        service = service_with_customer()
        session = service.impersonate(AGENT, CUSTOMER, TICKET)
        with self.assertRaises(ImpersonationForbidden):
            service.change_payout(session, ATTACKER_ACCOUNT)
        self.assertEqual(actions_by(service.audit_log, AGENT),
                         ["impersonation_started", "change_payout_account"])
        self.assertEqual(service.audit_log[-1].detail, "refused: impersonation session")

    def test_customer_can_still_change_their_own_payout(self):
        service = service_with_customer()
        own_session = Session(subject_id=CUSTOMER, actor_id=CUSTOMER)
        service.change_payout(own_session, "payout-new-bank")
        self.assertEqual(service.payout_accounts[CUSTOMER], "payout-new-bank")
        self.assertFalse(service.audit_log[-1].impersonated)

    def test_impersonation_without_a_ticket_is_rejected(self):
        with self.assertRaises(ValueError):
            service_with_customer().impersonate(AGENT, CUSTOMER, "  ")

    def test_staff_cannot_impersonate_themselves(self):
        with self.assertRaises(ValueError):
            service_with_customer().impersonate(AGENT, AGENT, TICKET)


if __name__ == "__main__":
    unittest.main()
