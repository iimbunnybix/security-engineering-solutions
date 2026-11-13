import os
import unittest

from solution import (
    TOKEN_LIFETIME_SECONDS,
    AccessDenied,
    UserRecord,
    UserStore,
    authorize,
    issue_token,
    naive_authorize,
)

LOGIN_TIME = 1_800_000_000.0
ONE_HOUR = 3600


def make_secret() -> bytes:
    """Fresh random signing key per test run; never a literal in the repo."""
    return os.urandom(32)


def store_with_admin() -> UserStore:
    return UserStore({"contractor-7": UserRecord(role="admin")})


class ReproduceProblem(unittest.TestCase):
    def test_demoted_admin_can_still_delete_with_old_token(self):
        secret, store = make_secret(), store_with_admin()
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        store.change_role("contractor-7", "viewer")
        # No exception: the token's "admin" claim is trusted for 12 hours.
        naive_authorize(secret, token, "delete_customer", LOGIN_TIME + 3 * ONE_HOUR)

    def test_deactivated_user_keeps_access_until_expiry(self):
        secret, store = make_secret(), store_with_admin()
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        store.deactivate("contractor-7")
        naive_authorize(secret, token, "read", LOGIN_TIME + 11 * ONE_HOUR)


class FixPermissionVersion(unittest.TestCase):
    def test_demotion_invalidates_existing_token_immediately(self):
        secret, store = make_secret(), store_with_admin()
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        store.change_role("contractor-7", "viewer")
        with self.assertRaises(AccessDenied):
            authorize(secret, store, token, "delete_customer", LOGIN_TIME + 1)

    def test_old_token_is_rejected_even_for_permissions_still_held(self):
        secret, store = make_secret(), store_with_admin()
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        store.change_role("contractor-7", "viewer")
        with self.assertRaisesRegex(AccessDenied, "sign in again"):
            authorize(secret, store, token, "read", LOGIN_TIME + 1)

    def test_new_token_after_demotion_has_only_viewer_rights(self):
        secret, store = make_secret(), store_with_admin()
        store.change_role("contractor-7", "viewer")
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        authorize(secret, store, token, "read", LOGIN_TIME + 1)
        with self.assertRaises(AccessDenied):
            authorize(secret, store, token, "delete_customer", LOGIN_TIME + 1)

    def test_deactivated_user_is_rejected(self):
        secret, store = make_secret(), store_with_admin()
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        store.deactivate("contractor-7")
        with self.assertRaisesRegex(AccessDenied, "not active"):
            authorize(secret, store, token, "read", LOGIN_TIME + 1)

    def test_unchanged_admin_keeps_working(self):
        secret, store = make_secret(), store_with_admin()
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        authorize(secret, store, token, "delete_customer", LOGIN_TIME + 11 * ONE_HOUR)

    def test_expired_token_is_rejected(self):
        secret, store = make_secret(), store_with_admin()
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        with self.assertRaisesRegex(AccessDenied, "expired"):
            authorize(secret, store, token, "read", LOGIN_TIME + TOKEN_LIFETIME_SECONDS)

    def test_token_signed_with_another_key_is_rejected(self):
        store = store_with_admin()
        token = issue_token(make_secret(), store, "contractor-7", LOGIN_TIME)
        with self.assertRaisesRegex(AccessDenied, "signature"):
            authorize(make_secret(), store, token, "read", LOGIN_TIME + 1)

    def test_deleted_user_is_rejected(self):
        secret, store = make_secret(), store_with_admin()
        token = issue_token(secret, store, "contractor-7", LOGIN_TIME)
        del store.users["contractor-7"]
        with self.assertRaises(AccessDenied):
            authorize(secret, store, token, "read", LOGIN_TIME + 1)


if __name__ == "__main__":
    unittest.main()
