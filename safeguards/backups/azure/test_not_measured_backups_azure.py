"""Bodies that prove nothing must read as not measured; real bodies must still be graded.

Token-Service grades a criterion unless additionalInfo.dataCollection.status is "error", so every
unmeasured path must return the key as None WITH a dataCollection error (value-keyed envelope).
A well-formed body that says "off" must still return False + "success", and one that says "on"
True + "success". Synthetic data only.
"""
import base64
import importlib.util
import json
import os
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("nm_azure_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


NO_EVIDENCE = [
    ("empty_dict", lambda: {}),
    ("empty_list", lambda: []),
    ("null", lambda: None),
    ("not_available", lambda: {"status": "Not Available"}),
    ("refusal_401", lambda: {"error": True, "statusCode": 401, "message": "invalid api key"}),
    ("refusal_403", lambda: {"error": {"type": "permission_error", "message": "Missing required scopes"}}),
    ("aws_access_denied", lambda: {"Error": {"Code": "AccessDenied", "Message": "not authorized"}}),
    ("poisoned", lambda: Poisoned()),
]


def days_ago(n, fmt="%Y-%m-%dT%H:%M:%SZ"):
    return (datetime.now(timezone.utc) - timedelta(days=n)).strftime(fmt)


def b64json(obj):
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("ascii")


ANY_VALUE = object()

FILES = [
    ("backupfrequency", "backupFrequency"),
    ("isgeoredundant", "isGeoRedundant"),
    ("lastsuccessfulbackupage", "lastSuccessfulBackupAge"),
    ("recoverytestcompleted", "recoveryTestCompleted"),
]

EXTRA_UNMEASURED = {
    # Resource Graph returns zero rows for resources the caller cannot read.
    "backupfrequency": [("rows_empty", lambda: {"data": {"rows": []}})],
    "isgeoredundant": [("vault_without_storage_type", lambda: {"value": [{"name": "v1", "properties": {}}]})],
    "lastsuccessfulbackupage": [("no_protected_items", lambda: {"value": []})],
    "recoverytestcompleted": [("value_not_a_list", lambda: {"value": None})],
}


def policy(schedule_type):
    return {"data": {"rows": [[{"name": "p1", "vaultName": "v1", "scheduleType": schedule_type, "hasSchedule": True}]]}}


def vaults(redundancy):
    return {"value": [{"name": "v1", "properties": {"redundancySettings": {"standardTierStorageRedundancy": redundancy}}}]}


MEASURED = {
    "backupfrequency": [
        ("weekly_policy", lambda: policy("Weekly"), False),
        ("daily_policy", lambda: policy("Daily"), True),
        ("legacy_weekly_minutes", lambda: {"properties": {"schedulePolicy": {"scheduleFrequencyInMins": 10080}}}, False),
    ],
    "isgeoredundant": [
        ("locally_redundant", lambda: vaults("LocallyRedundant"), False),
        ("geo_redundant", lambda: vaults("GeoRedundant"), True),
    ],
    "lastsuccessfulbackupage": [
        ("recent_backup", lambda: {"value": [{"properties": {"lastBackupTime": days_ago(1)}}]}, ANY_VALUE),
    ],
    "recoverytestcompleted": [
        ("no_jobs", lambda: {"value": []}, False),
        ("recent_restore", lambda: {"value": [{"properties": {"operation": "Restore", "status": "Completed", "endTime": days_ago(30)}}]}, True),
    ],
}


class AgeIsStillComputed(unittest.TestCase):
    def test_measured_age_is_hours_as_a_string(self):
        value, collection = run("lastsuccessfulbackupage", "lastSuccessfulBackupAge",
                                {"value": [{"properties": {"lastBackupTime": days_ago(2)}}]})
        self.assertEqual(collection["status"], "success")
        self.assertIsInstance(value, str)
        self.assertTrue(47 <= int(value) <= 49)


def run(name, key, body):
    out = load(name).transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]


class NotMeasuredIsNotGraded(unittest.TestCase):
    def test_no_evidence_reads_as_not_measured(self):
        for name, key in FILES:
            for case, body in NO_EVIDENCE + EXTRA_UNMEASURED.get(name, []):
                with self.subTest(transform=name, body=case):
                    value, collection = run(name, key, body())
                    self.assertIsNone(value)
                    self.assertEqual(collection["status"], "error")
                    self.assertTrue(collection["errors"])
                    self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))

    def test_measured_answers_are_still_graded(self):
        for name, key in FILES:
            for case, body, expected in MEASURED.get(name, []):
                with self.subTest(transform=name, body=case):
                    value, collection = run(name, key, body())
                    if expected is ANY_VALUE:
                        self.assertIsNotNone(value)
                    else:
                        self.assertIs(value, expected)
                    self.assertEqual(collection["status"], "success")
                    self.assertEqual(collection["errors"], [])

    def test_every_file_has_a_measured_case(self):
        for name, _key in FILES:
            self.assertTrue(MEASURED.get(name), name)


# The five Resource Graph readers whose except and input-validation branches used to answer False.
# A body that raises, or fails input validation, measured nothing, so it must read as not measured.
RAISING_READERS = [
    ("isbackupenabled", "isBackupEnabled"),
    ("is_backup_types_scheduled", "isBackupTypesScheduled"),
    ("is_backup_tested", "isBackupTested"),
    ("is_backup_encrypted", "isBackupEncrypted"),
    ("is_backup_immutable", "isBackupImmutable"),
]


class RaisingBodyIsNotGraded(unittest.TestCase):
    def test_a_body_that_raises_reads_as_not_measured(self):
        for name, key in RAISING_READERS:
            with self.subTest(transform=name):
                value, collection = run(name, key, Poisoned())
                self.assertIsNone(value)
                self.assertEqual(collection["status"], "error")
                self.assertTrue(collection["errors"])

    def test_a_body_that_fails_input_validation_reads_as_not_measured(self):
        # extract_input is stubbed so that ONLY the input-validation branch can decide the answer:
        # with the data absent, a branch that returned False would be graded red here.
        failed = {"status": "failed", "errors": ["bad shape"], "warnings": []}
        for name, key in RAISING_READERS:
            with self.subTest(transform=name):
                module = load(name)
                module.extract_input = lambda _input, _failed=failed: (None, _failed)
                out = module.transform({"any": "body"})
                self.assertIsNone(out["transformedResponse"][key])
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
