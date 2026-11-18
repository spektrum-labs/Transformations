"""is_backup_encrypted (AWS): no backups is not proof of encryption (ENG-1352).

Every section read and none holding a backup used to report isBackupEncrypted True ("No backups
found to evaluate encryption"). It is now Not evaluated: value None with dataCollection "error".
Synthetic fixtures only.
"""
import copy
import importlib.util
import unittest
from pathlib import Path


def load():
    spec = importlib.util.spec_from_file_location("aws_is_backup_encrypted_eng1352",
                                                  Path(__file__).with_name("is_backup_encrypted.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def body(auto=None, manual=None, ebs=None):
    return {"result": {
        "dbBackups": {"DescribeDBInstanceAutomatedBackupsResponse": {"DescribeDBInstanceAutomatedBackupsResult": {
            "DBInstanceAutomatedBackups": {"DBInstanceAutomatedBackup": auto} if auto is not None else None}}},
        "dbManualSnapshots": {"DescribeDBSnapshotsResponse": {"DescribeDBSnapshotsResult": {
            "DBSnapshots": {"DBSnapshot": manual} if manual is not None else None}}},
        "volumeSnapshots": {"DescribeSnapshotsResponse": {"snapshotSet": {"item": ebs} if ebs is not None else None}},
    }}


AUTO_ENCRYPTED = [{"DBInstanceIdentifier": "db-synthetic-1", "Encrypted": "true"}]
EBS_UNENCRYPTED = [{"snapshotId": "snap-00000000000000001", "encrypted": "false"}]

KEYS = ("isBackupEncrypted", "isAutoBackupEncrypted", "isManualBackupEncrypted", "isEbsBackupEncrypted")


class NoBackupsIsNotEvaluated(unittest.TestCase):
    mod = load()

    def test_three_empty_sections_are_not_evaluated(self):
        out = self.mod.transform(body())
        for key in KEYS:
            self.assertIsNone(out["transformedResponse"][key], key)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_empty_lists_are_not_evaluated(self):
        out = self.mod.transform(body(auto=[], manual=[], ebs=[]))
        self.assertIsNone(out["transformedResponse"]["isBackupEncrypted"])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_one_encrypted_backup_passes(self):
        out = self.mod.transform(body(auto=copy.deepcopy(AUTO_ENCRYPTED)))
        self.assertIs(out["transformedResponse"]["isBackupEncrypted"], True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_an_unencrypted_snapshot_still_fails(self):
        out = self.mod.transform(body(auto=copy.deepcopy(AUTO_ENCRYPTED), ebs=copy.deepcopy(EBS_UNENCRYPTED)))
        self.assertIs(out["transformedResponse"]["isBackupEncrypted"], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")


if __name__ == "__main__":
    unittest.main()
