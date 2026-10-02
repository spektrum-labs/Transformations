import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("is_backup_immutable", HERE / "is_backup_immutable.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def vault(name, lock_date, points=35):
    return {"BackupVaultName": name, "Locked": True, "LockDate": lock_date.timestamp(),
            "NumberOfRecoveryPoints": points, "MinRetentionDays": 30}


class GracePeriodTests(unittest.TestCase):
    def test_future_lock_date_fails_with_cooling_off_reason(self):
        future = datetime.now(timezone.utc) + timedelta(days=2)
        out = mod.transform({"BackupVaultList": [vault("neptune-prod-vault", future)]})
        self.assertIs(out["transformedResponse"]["isBackupImmutable"], False)
        reasons = " ".join(out["additionalInfo"]["evaluation"]["failReasons"])
        self.assertIn("neptune-prod-vault: Vault Lock applied in compliance mode; becomes immutable on", reasons)
        self.assertIn("Until then the lock can be removed.", reasons)
        recs = " ".join(out["additionalInfo"]["evaluation"]["recommendations"])
        self.assertIn("cooling-off period of at least 3 days", recs)
        self.assertNotIn("Apply AWS Backup Vault Lock", recs)

    def test_past_lock_date_passes(self):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        out = mod.transform({"BackupVaultList": [vault("neptune-prod-vault", past)]})
        self.assertIs(out["transformedResponse"]["isBackupImmutable"], True)
        self.assertEqual(out["additionalInfo"]["evaluation"]["failReasons"], [])

    def test_mixed_unlocked_and_grace(self):
        future = datetime.now(timezone.utc) + timedelta(days=2)
        out = mod.transform({"BackupVaultList": [vault("a", future),
                                                 {"BackupVaultName": "b", "Locked": False, "NumberOfRecoveryPoints": 3}]})
        self.assertIs(out["transformedResponse"]["isBackupImmutable"], False)
        recs = " ".join(out["additionalInfo"]["evaluation"]["recommendations"])
        self.assertIn("Apply AWS Backup Vault Lock", recs)
        self.assertIn("cooling-off", recs)

    def test_eastern_formatting(self):
        self.assertEqual(mod.eastern(datetime(2026, 10, 3, 18, 43, tzinfo=timezone.utc)), "03 Oct 2026 14:43 EDT")
        self.assertEqual(mod.eastern(datetime(2026, 12, 3, 18, 43, tzinfo=timezone.utc)), "03 Dec 2026 13:43 EST")


if __name__ == "__main__":
    unittest.main()
