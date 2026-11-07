import secrets
import unittest

from solution import (PROFILE_UPDATE, Forbidden, User, ValidationError, admin_update_user,
                      naive_update_profile, serialize, update_profile)


def make_user(uid=1, role="member", org=10):
    # Fake hash built at runtime; never a real-looking literal.
    return User(id=uid, email=f"user{uid}@example.com", display_name=f"User {uid}",
                org_id=org, role=role, password_hash="pbkdf2$" + secrets.token_hex(8))


ATTACK = {"display_name": "Mallory", "role": "admin", "email_verified": True,
          "credit_cents": 10_000_000, "org_id": 99}


class ReproduceMassAssignment(unittest.TestCase):
    def test_member_becomes_admin_and_moves_org(self):
        u = naive_update_profile(make_user(), dict(ATTACK))
        self.assertEqual((u.role, u.email_verified, u.credit_cents, u.org_id),
                         ("admin", True, 10_000_000, 99))

    def test_type_confusion_also_accepted(self):
        u = naive_update_profile(make_user(), {"marketing_opt_in": "yes please"})
        self.assertEqual(u.marketing_opt_in, "yes please")


class ProfileUpdate(unittest.TestCase):
    def setUp(self):
        self.user, self.audit = make_user(), []

    def test_attack_rejected_and_nothing_changes(self):
        before = serialize(self.user, self.user), self.user.credit_cents, self.user.org_id
        with self.assertRaises(ValidationError) as ctx:
            update_profile(self.user, self.user, dict(ATTACK), self.audit)
        self.assertEqual(sorted(ctx.exception.errors), [
            "unknown field 'credit_cents'", "unknown field 'email_verified'",
            "unknown field 'org_id'", "unknown field 'role'"])
        self.assertEqual((serialize(self.user, self.user), self.user.credit_cents,
                          self.user.org_id), before)
        self.assertEqual(self.audit, [])

    def test_allowed_fields_update_and_are_audited(self):
        update_profile(self.user, self.user, {"display_name": "Asha", "timezone": "Asia/Kolkata",
                                              "marketing_opt_in": True}, self.audit)
        self.assertEqual((self.user.display_name, self.user.timezone), ("Asha", "Asia/Kolkata"))
        self.assertEqual(sorted(a["field"] for a in self.audit),
                         ["display_name", "marketing_opt_in", "timezone"])

    def test_types_and_limits(self):
        for body in [{"marketing_opt_in": "true"}, {"marketing_opt_in": 1},
                     {"display_name": ""}, {"display_name": "x" * 51},
                     {"display_name": " padded"}, {"display_name": "a\u0000b"},
                     {"timezone": "Mars/Base"}, {"bio": None}, {"bio": ["list"]}]:
            with self.assertRaises(ValidationError, msg=body):
                update_profile(self.user, self.user, body, self.audit)

    def test_non_object_body(self):
        with self.assertRaises(ValidationError):
            update_profile(self.user, self.user, ["role", "admin"], self.audit)

    def test_cannot_edit_someone_else(self):
        with self.assertRaises(Forbidden):
            update_profile(make_user(2), self.user, {"bio": "hi"}, self.audit)

    def test_lenient_mode_drops_and_logs(self):
        log = []
        data = PROFILE_UPDATE.parse({"bio": "ok", "role": "admin"}, strict=False, log=log)
        self.assertEqual(data, {"bio": "ok"})
        self.assertEqual(log, ["profile_update: dropped 1 unknown field(s): 'role'"])

    def test_newline_in_unknown_key_cannot_forge_a_log_line(self):
        log = []
        forged_key = "x'\n2026-11-05 admin_user_update: role changed to admin\n"
        PROFILE_UPDATE.parse({"bio": "ok", forged_key: 1}, strict=False, log=log)
        self.assertEqual(len(log), 1)
        self.assertNotIn("\n", log[0])

    def test_many_unknown_keys_produce_one_bounded_log_entry(self):
        log = []
        body = {f"k{index}": 1 for index in range(50_000)}
        PROFILE_UPDATE.parse(body, strict=False, log=log)
        self.assertEqual(len(log), 1)
        self.assertIn("dropped 50000 unknown field(s)", log[0])
        self.assertIn("'k19'", log[0])
        self.assertNotIn("'k20'", log[0])
        self.assertLess(len(log[0]), 2_000)

    def test_very_long_unknown_key_is_truncated_in_the_log(self):
        log = []
        PROFILE_UPDATE.parse({"a" * 10_000: 1}, strict=False, log=log)
        self.assertLess(len(log[0]), 200)


class AdminUpdate(unittest.TestCase):
    def test_admin_can_change_role_in_same_org(self):
        admin, target, audit = make_user(1, "admin"), make_user(2), []
        admin_update_user(admin, target, {"role": "billing"}, audit)
        self.assertEqual(target.role, "billing")
        self.assertEqual(audit, [{"actor": 1, "user": 2, "field": "role"}])

    def test_member_cannot_use_admin_endpoint(self):
        with self.assertRaises(Forbidden):
            admin_update_user(make_user(1), make_user(1), {"role": "admin"}, [])

    def test_admin_cannot_touch_other_org_or_own_role_or_credit(self):
        admin = make_user(1, "admin")
        with self.assertRaises(Forbidden):
            admin_update_user(admin, make_user(2, org=11), {"role": "admin"}, [])
        with self.assertRaises(Forbidden):
            admin_update_user(admin, admin, {"role": "member"}, [])
        with self.assertRaises(ValidationError):
            admin_update_user(admin, make_user(2), {"credit_cents": 5}, [])
        with self.assertRaises(ValidationError):
            admin_update_user(admin, make_user(2), {"role": "superuser"}, [])


class OutputAllowlist(unittest.TestCase):
    def test_password_hash_never_serialised(self):
        u = make_user()
        for viewer in (u, make_user(2)):
            self.assertNotIn("password_hash", serialize(u, viewer))
            self.assertNotIn("credit_cents", serialize(u, viewer))

    def test_others_see_public_fields_only(self):
        self.assertEqual(set(serialize(make_user(1), make_user(2))),
                         {"id", "display_name", "bio", "timezone"})
        self.assertIn("email", serialize(make_user(1), make_user(1)))


if __name__ == "__main__":
    unittest.main()
