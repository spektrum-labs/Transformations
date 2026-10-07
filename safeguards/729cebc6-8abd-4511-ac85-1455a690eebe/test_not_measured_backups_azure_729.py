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
    spec = importlib.util.spec_from_file_location("nm_azure_729_" + name, os.path.join(HERE, name + ".py"))
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
    ("isbackupenabled", "isBackupEnabled"),
    ("is_backup_enabled_for_critical_systems", "isBackupEnabledForCriticalSystems"),
    ("is_backup_logging_enabled", "isBackupLoggingEnabled"),
    ("is_backup_tested", "isBackupTested"),
    ("is_backup_types_scheduled", "isBackupTypesScheduled"),
]

EXTRA_UNMEASURED = {
    "isbackupenabled": [("data_without_rows", lambda: {"data": {"columns": []}})],
    "is_backup_types_scheduled": [("data_without_rows", lambda: {"data": {"columns": []}})],
    "is_backup_logging_enabled": [("diagnostic_settings_stub", lambda: {"diagnosticSettings": [{"status": "Not Available"}]})],
}


def auto_backups(group):
    return {"dbBackups": {"DescribeDBInstanceAutomatedBackupsResponse": {
        "DescribeDBInstanceAutomatedBackupsResult": {"DBInstanceAutomatedBackups": group}}}}


def setting(enabled):
    return {"value": [{"name": "s1", "properties": {
        "logs": [{"category": "AzureBackupReport", "enabled": enabled}], "workspaceId": "/workspaces/w1"}}]}


def restore(status):
    return {"value": [{"id": "j1", "properties": {"operation": "Restore", "status": status, "endTime": days_ago(20)}}]}


MEASURED = {
    "isbackupenabled": [
        ("rows_empty", lambda: {"data": {"rows": []}}, False),
        ("rows_present", lambda: {"data": {"rows": [["vault-1"]]}}, True),
    ],
    "is_backup_enabled_for_critical_systems": [
        ("no_automated_backups", lambda: auto_backups({}), False),
        ("one_automated_backup", lambda: auto_backups({"DBInstanceAutomatedBackup": {"DBInstanceIdentifier": "db1"}}), True),
    ],
    "is_backup_logging_enabled": [
        ("no_settings", lambda: {"value": []}, False),
        ("log_category_disabled", lambda: setting(False), False),
        ("log_category_enabled", lambda: setting(True), True),
    ],
    "is_backup_tested": [
        ("no_restore_jobs", lambda: {"value": []}, False),
        ("failed_restore", lambda: restore("Failed"), False),
        ("successful_restore", lambda: restore("Completed"), True),
    ],
    "is_backup_types_scheduled": [
        ("rows_empty", lambda: {"data": {"rows": []}}, False),
        ("zero_protected_items", lambda: {"data": {"rows": [{"properties": {"protectedItemsCount": 0}}]}}, False),
        ("protected_items", lambda: {"data": {"rows": [{"properties": {"protectedItemsCount": 3}}]}}, True),
    ],
}


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


if __name__ == "__main__":
    unittest.main()
