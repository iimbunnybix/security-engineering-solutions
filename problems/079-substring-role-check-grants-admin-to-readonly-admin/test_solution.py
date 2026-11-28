import unittest

from solution import (MalformedRoleClaim, User, delete_account, has_role, is_admin,
                      original_is_admin, parse_roles)

LOOKALIKE_ROLES = ["readonly-admin", "billing-admin-viewer", "notadmin", "administrator",
                   "sysadmin-trainee"]


class ReproduceProblem(unittest.TestCase):
    def test_every_lookalike_role_passes_the_original_check(self):
        for role in LOOKALIKE_ROLES:
            self.assertTrue(original_is_admin(User("sam", f"support,{role}")), role)

    def test_readonly_support_user_can_delete_an_account(self):
        deleted: list[str] = []
        status = delete_account(User("sam", "support,readonly-admin"), "acct-42", deleted,
                                admin_check=original_is_admin)
        self.assertEqual(status, 204)
        self.assertEqual(deleted, ["acct-42"])


class FixExactRoleMembership(unittest.TestCase):
    def test_lookalike_roles_are_not_admin(self):
        for role in LOOKALIKE_ROLES:
            self.assertFalse(is_admin(User("sam", f"support,{role}")), role)

    def test_readonly_support_user_gets_403(self):
        deleted: list[str] = []
        status = delete_account(User("sam", "support,readonly-admin"), "acct-42", deleted)
        self.assertEqual(status, 403)
        self.assertEqual(deleted, [])

    def test_real_admin_is_allowed(self):
        deleted: list[str] = []
        self.assertEqual(delete_account(User("ana", "support,admin"), "acct-42", deleted), 204)

    def test_spacing_and_case_from_the_idp_are_tolerated(self):
        self.assertTrue(is_admin(User("ana", " Support , ADMIN ")))

    def test_empty_entries_are_ignored(self):
        self.assertEqual(parse_roles("support,,admin,"), frozenset({"support", "admin"}))

    def test_empty_claim_has_no_roles(self):
        self.assertFalse(is_admin(User("guest", "")))

    def test_malformed_claim_is_rejected_when_parsing(self):
        with self.assertRaises(MalformedRoleClaim):
            parse_roles("support;admin")

    def test_malformed_claim_fails_closed(self):
        self.assertFalse(is_admin(User("eve", "support admin")))

    def test_other_roles_are_checked_exactly_too(self):
        self.assertTrue(has_role(User("li", "billing-admin-viewer"), "billing-admin-viewer"))
        self.assertFalse(has_role(User("li", "billing-admin-viewer"), "billing"))


if __name__ == "__main__":
    unittest.main()
