import unittest

from solution import RoleChangeDenied, Workspace, assign_role, naive_assign_role, remove_member


def build_workspace():
    """One owner, one manager (the attacker), one member, one billing admin."""
    return Workspace(roles={
        "olivia": "owner",
        "mallory": "manager",
        "sam": "member",
        "bea": "billing_admin",
    })


class ReproduceProblem(unittest.TestCase):
    def setUp(self):
        self.workspace = build_workspace()

    def test_manager_invites_accomplice_as_owner(self):
        naive_assign_role(self.workspace, "mallory", "accomplice", "owner")
        self.assertIn("workspace:delete", self.workspace.permissions_of("accomplice"))

    def test_manager_promotes_himself_to_owner(self):
        naive_assign_role(self.workspace, "mallory", "mallory", "owner")
        self.assertEqual(self.workspace.roles["mallory"], "owner")

    def test_manager_demotes_the_only_owner(self):
        naive_assign_role(self.workspace, "mallory", "olivia", "viewer")
        self.assertEqual(self.workspace.owner_count(), 0)


class FixDelegationLimits(unittest.TestCase):
    def setUp(self):
        self.workspace = build_workspace()

    def assert_denied(self, actor, target, role):
        before = dict(self.workspace.roles)
        with self.assertRaises(RoleChangeDenied):
            assign_role(self.workspace, actor, target, role)
        self.assertEqual(self.workspace.roles, before)

    def test_manager_cannot_invite_anyone_as_owner(self):
        self.assert_denied("mallory", "accomplice", "owner")

    def test_manager_cannot_change_own_role(self):
        self.assert_denied("mallory", "mallory", "owner")

    def test_manager_cannot_grant_custom_role_with_permission_he_lacks(self):
        # billing_admin is not "above" manager, but it can issue refunds.
        self.assert_denied("mallory", "sam", "billing_admin")

    def test_manager_cannot_demote_an_owner(self):
        self.assert_denied("mallory", "olivia", "viewer")

    def test_manager_can_invite_and_promote_within_his_own_permissions(self):
        assign_role(self.workspace, "mallory", "new-hire", "member")
        assign_role(self.workspace, "mallory", "sam", "manager")
        self.assertEqual(self.workspace.roles["new-hire"], "member")
        self.assertEqual(self.workspace.roles["sam"], "manager")

    def test_member_without_change_permission_cannot_grant_anything(self):
        self.assert_denied("sam", "friend", "viewer")

    def test_non_member_cannot_grant_anything(self):
        self.assert_denied("stranger", "friend", "viewer")

    def test_unknown_role_is_rejected(self):
        self.assert_denied("olivia", "sam", "superuser")

    def test_owner_can_appoint_a_second_owner(self):
        assign_role(self.workspace, "olivia", "sam", "owner")
        self.assertEqual(self.workspace.owner_count(), 2)

    def test_ownership_can_be_handed_over_by_adding_an_owner_first(self):
        assign_role(self.workspace, "olivia", "sam", "owner")
        assign_role(self.workspace, "sam", "olivia", "member")
        self.assertEqual(self.workspace.roles["olivia"], "member")
        self.assertEqual(self.workspace.owner_count(), 1)


class FixMemberRemoval(unittest.TestCase):
    def setUp(self):
        self.workspace = build_workspace()

    def test_manager_cannot_remove_the_owner(self):
        with self.assertRaises(RoleChangeDenied):
            remove_member(self.workspace, "mallory", "olivia")
        self.assertIn("olivia", self.workspace.roles)

    def test_manager_can_remove_a_member(self):
        remove_member(self.workspace, "mallory", "sam")
        self.assertNotIn("sam", self.workspace.roles)

    def test_last_owner_cannot_remove_herself(self):
        with self.assertRaises(RoleChangeDenied):
            remove_member(self.workspace, "olivia", "olivia")

    def test_removing_a_non_member_is_rejected(self):
        with self.assertRaises(RoleChangeDenied):
            remove_member(self.workspace, "olivia", "ghost")


if __name__ == "__main__":
    unittest.main()
