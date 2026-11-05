import secrets
import unittest

from solution import (InvalidInvite, accept_invite, canonical, forge_admin_invite,
                      issue_invite, naive_accept_invite, naive_canonical,
                      naive_issue_invite)

ATTACK_EMAIL = "eve@evil.test&role=admin&z="


def make_key() -> bytes:
    return secrets.token_bytes(32)


class ReproduceProblem(unittest.TestCase):
    def test_two_different_param_sets_share_one_canonical_string(self):
        requested = {"email": ATTACK_EMAIL, "role": "viewer"}
        forged = {"email": "eve@evil.test", "role": "admin", "z": "&role=viewer"}
        self.assertEqual(naive_canonical(requested), naive_canonical(forged))

    def test_self_service_invite_is_forged_into_admin(self):
        key = make_key()
        issued = naive_issue_invite(key, ATTACK_EMAIL)
        forged = forge_admin_invite(issued)
        self.assertEqual(naive_accept_invite(key, forged), ("eve@evil.test", "admin"))


class FixSignedInvites(unittest.TestCase):
    def test_genuine_invite_is_accepted(self):
        key = make_key()
        issued = issue_invite(key, "asha@example.test")
        self.assertEqual(accept_invite(key, issued), ("asha@example.test", "viewer"))

    def test_attack_email_is_refused_at_issue_time(self):
        with self.assertRaises(InvalidInvite):
            issue_invite(make_key(), ATTACK_EMAIL)

    def test_forged_params_are_rejected_even_with_old_signature(self):
        key = make_key()
        issued = naive_issue_invite(key, ATTACK_EMAIL)
        with self.assertRaises(InvalidInvite):
            accept_invite(key, forge_admin_invite(issued))

    def test_extra_parameter_is_rejected(self):
        key = make_key()
        issued = issue_invite(key, "asha@example.test")
        issued["z"] = "1"
        with self.assertRaises(InvalidInvite):
            accept_invite(key, issued)

    def test_missing_parameter_is_rejected(self):
        key = make_key()
        issued = issue_invite(key, "asha@example.test")
        del issued["role"]
        with self.assertRaises(InvalidInvite):
            accept_invite(key, issued)

    def test_changing_role_breaks_signature(self):
        key = make_key()
        issued = issue_invite(key, "asha@example.test")
        issued["role"] = "admin"
        with self.assertRaises(InvalidInvite):
            accept_invite(key, issued)

    def test_signature_from_another_key_is_rejected(self):
        issued = issue_invite(make_key(), "asha@example.test")
        with self.assertRaises(InvalidInvite):
            accept_invite(make_key(), issued)

    def test_length_prefixed_encoding_separates_shifted_values(self):
        first = canonical({"email": "ab", "role": "c"})
        second = canonical({"email": "a", "role": "bc"})
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
