import dataclasses
import secrets
import unittest

from solution import AuditLog, plain_log_detects_tampering


def new_log():
    log = AuditLog({"k1": secrets.token_bytes(32)}, "k1")   # test key built at runtime
    log.append(100.0, "admin:meera", "role.grant", "user:42", {"role": "finance_admin"})
    log.append(160.0, "admin:meera", "payout.update", "merchant:7", {"iban_last4": "9921"})
    log.append(220.0, "admin:arun", "export.users", "tenant:acme", {"rows": 18000})
    log.append(300.0, "admin:arun", "role.revoke", "user:42", {"role": "finance_admin"})
    return log


def edit(entry, **changes):
    return dataclasses.replace(entry, **changes)


class ReproduceUnprovableLog(unittest.TestCase):
    def test_plain_table_edits_and_deletes_are_invisible(self):
        rows = [{"ts": 1, "actor": "admin:arun", "action": "export.users", "target": "tenant:acme"},
                {"ts": 2, "actor": "admin:arun", "action": "role.revoke", "target": "user:42"}]
        edited = [dict(rows[0], actor="admin:meera"), rows[1]]
        deleted = rows[1:]
        self.assertFalse(plain_log_detects_tampering(rows, edited))
        self.assertFalse(plain_log_detects_tampering(rows, deleted))


class HashChain(unittest.TestCase):
    def test_intact_log_verifies(self):
        log = new_log()
        log.checkpoint()
        self.assertTrue(log.verify().ok)

    def test_edited_field_detected(self):
        log = new_log()
        log.entries[2] = edit(log.entries[2], actor="admin:meera")   # blame someone else
        r = log.verify()
        self.assertEqual((r.ok, r.first_bad_seq), (False, 3))
        self.assertIn("modified", r.reason)

    def test_edited_details_detected(self):
        log = new_log()
        log.entries[2] = edit(log.entries[2], details={"rows": 18})
        self.assertEqual(log.verify().first_bad_seq, 3)

    def test_deleted_middle_entry_detected(self):
        log = new_log()
        del log.entries[1]
        r = log.verify()
        self.assertEqual((r.ok, r.first_bad_seq), (False, 3))
        self.assertIn("sequence gap", r.reason)

    def test_deleted_and_renumbered_detected(self):
        log = new_log()
        del log.entries[1]
        log.entries[1:] = [edit(e, seq=e.seq - 1) for e in log.entries[1:]]
        r = log.verify()
        self.assertFalse(r.ok)
        self.assertEqual(r.first_bad_seq, 2)

    def test_reordering_detected(self):
        log = new_log()
        log.entries[1], log.entries[2] = log.entries[2], log.entries[1]
        self.assertFalse(log.verify().ok)

    def test_forged_entry_without_key_detected(self):
        log = new_log()
        last = log.entries[-1]
        forged = edit(last, seq=5, prev_mac=last.mac, action="role.grant", mac="ab" * 32)
        log.entries.append(forged)
        r = log.verify()
        self.assertEqual((r.ok, r.first_bad_seq), (False, 5))

    def test_tail_truncation_needs_checkpoint(self):
        log = new_log()
        log.checkpoint()                        # head = seq 4 copied to write-once storage
        del log.entries[-1]                     # quietly drop the latest action
        r = log.verify()
        self.assertFalse(r.ok)
        self.assertIn("truncated", r.reason)

    def test_rewritten_history_mismatches_checkpoint(self):
        keys = {"k1": secrets.token_bytes(32)}
        log = AuditLog(keys, "k1")
        log.append(1.0, "a", "x", "t")
        log.checkpoint()
        # An insider who *does* have the key rebuilds the chain with different content;
        # the external checkpoint still exposes it.
        rebuilt = AuditLog(keys, "k1")
        rebuilt.append(1.0, "b", "x", "t")
        log.entries = rebuilt.entries
        r = log.verify()
        self.assertIn("checkpoint mismatch", r.reason)


class KeyRotation(unittest.TestCase):
    def test_entries_from_old_and_new_keys_verify(self):
        log = new_log()
        log.rotate_key("k2", secrets.token_bytes(32))
        e = log.append(400.0, "admin:meera", "role.grant", "user:9")
        self.assertEqual(e.key_id, "k2")
        self.assertTrue(log.verify().ok)

    def test_missing_key_reported(self):
        log = new_log()
        del log.keys["k1"]
        r = log.verify()
        self.assertEqual((r.ok, r.first_bad_seq), (False, 1))

    def test_invalid_active_key(self):
        with self.assertRaises(ValueError):
            AuditLog({}, "k1")

    def test_canonical_serialization_ignores_dict_order(self):
        log = AuditLog({"k1": secrets.token_bytes(32)}, "k1")
        log.append(1.0, "a", "x", "t", {"b": 2, "a": 1})
        log.entries[0] = edit(log.entries[0], details={"a": 1, "b": 2})
        self.assertTrue(log.verify().ok)

    def test_empty_log(self):
        log = AuditLog({"k1": secrets.token_bytes(32)}, "k1")
        self.assertEqual(log.checkpoint(), (0, "0" * 64))
        self.assertTrue(log.verify().ok)


if __name__ == "__main__":
    unittest.main()
