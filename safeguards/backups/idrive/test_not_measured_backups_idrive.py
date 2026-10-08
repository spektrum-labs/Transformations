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
    spec = importlib.util.spec_from_file_location("nm_idrive_" + name, os.path.join(HERE, name + ".py"))
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
    ("isBackupEnabled", "isBackupEnabled"),
    ("isBackupTypesScheduled", "isBackupTypesScheduled"),
    ("isBareMetalRecoveryEnabled", "isBareMetalRecoveryEnabled"),
    ("isJobExecutionLogAccessible", "isJobExecutionLogAccessible"),
    ("isPrivateKeyEncryptionEnforced", "isPrivateKeyEncryptionEnforced"),
    ("isSubCompanyDataIsolationEnforced", "isSubCompanyDataIsolationEnforced"),
]

EXTRA_UNMEASURED = {
    "isBackupEnabled": [("plan_without_flag", lambda: {"data": [{"name": "plan-1"}]})],
    "isBareMetalRecoveryEnabled": [("plan_without_backup_type", lambda: {"data": [{"id": "plan-1", "is_enabled": True}]})],
    "isPrivateKeyEncryptionEnforced": [("undecodable_config", lambda: {"company_id": 1, "name": "c", "configuration_id": "!!"})],
}


def plan(**fields):
    return {"data": [dict({"id": "plan-1", "name": "plan-1"}, **fields)]}


def device(last_backup):
    return {"data": [{"device_id": "d1", "backup_status": "success", "last_backup": last_backup, "next_backup": "2026-10-08"}]}


def company(required):
    return {"company_id": 1, "name": "c", "configuration_id": b64json({"encryptionRequired": required})}


MEASURED = {
    "isBackupEnabled": [
        ("plan_disabled", lambda: plan(is_enabled=False), False),
        ("plan_enabled", lambda: plan(is_enabled=True), True),
    ],
    "isBackupTypesScheduled": [
        ("manual_only", lambda: plan(is_enabled=True, schedule_info={"frequency_type": "MANUAL"}), False),
        ("daily", lambda: plan(is_enabled=True, schedule_info={"frequency_type": "DAILY"}), True),
    ],
    "isBareMetalRecoveryEnabled": [
        ("files_only", lambda: plan(is_enabled=True, backup_details={"what_to_backup": "FILES_AND_FOLDERS"}), False),
        ("entire_machine", lambda: plan(is_enabled=True, backup_details={"what_to_backup": "ENTIRE_MACHINE"}), True),
    ],
    "isJobExecutionLogAccessible": [
        ("missing_last_backup", lambda: device(""), False),
        ("all_fields", lambda: device("2026-10-06"), True),
    ],
    "isPrivateKeyEncryptionEnforced": [
        ("default_key", lambda: company(False), False),
        ("private_key", lambda: company(True), True),
    ],
    "isSubCompanyDataIsolationEnforced": [
        ("sub_shares_parent_id", lambda: {"company_id": 1, "name": "c", "sub_company_list": [{"company_id": 1}]}, False),
        ("distinct_sub_ids", lambda: {"company_id": 1, "name": "c", "sub_company_list": [{"company_id": 2}]}, True),
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
