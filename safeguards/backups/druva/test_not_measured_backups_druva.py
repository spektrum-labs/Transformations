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
    spec = importlib.util.spec_from_file_location("nm_druva_" + name, os.path.join(HERE, name + ".py"))
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
    ("isbackupenabledforcriticalsystems", "isBackupEnabledForCriticalSystems"),
    ("isbackuploggingenabled", "isBackupLoggingEnabled"),
    ("isbackuptested", "isBackupTested"),
]


def report(rows):
    return {"data": rows, "lastSyncTimestamp": "2026-10-06T00:00:00Z", "filters": {}}


EMPTY_REPORT = [("empty_report", lambda: report([]))]

EXTRA_UNMEASURED = {
    "isbackupenabled": EMPTY_REPORT,
    "isbackupenabledforcriticalsystems": EMPTY_REPORT,
    # An empty audit trail proves nothing, so it has no measured-False path at all.
    "isbackuploggingenabled": EMPTY_REPORT + [("rows_without_action", lambda: report([{"lastUpdatedTime": "2026-10-01T00:00:00"}]))],
}

# getRestoreActivity asks for every restore since 2000-01-01, so an empty Restore Activity report -- and
# the bare [] Token-Service hands a legacy transform after drilling to the row list -- is a measured
# "no restore ever recorded", not an absent reading.
MEASURED_WHEN_EMPTY = {"isbackuptested": ("empty_list",)}

MEASURED = {
    "isbackupenabled": [
        ("backup_disabled", lambda: report([{"resourceName": "r1", "backupEnabled": "No"}]), False),
        ("backup_enabled", lambda: report([{"resourceName": "r1", "backupEnabled": "Yes"}]), True),
    ],
    "isbackupenabledforcriticalsystems": [
        ("one_disabled", lambda: report([{"resourceName": "r1", "backupEnabled": "Yes"},
                                         {"resourceName": "r2", "backupEnabled": "No"}]), False),
        ("all_enabled", lambda: report([{"resourceName": "r1", "backupEnabled": "Yes"}]), True),
    ],
    "isbackuploggingenabled": [
        ("admin_action", lambda: report([{"actionName": "Login", "lastUpdatedTime": "2026-10-01T00:00:00"}]), True),
    ],
    "isbackuptested": [
        ("failed_restore", lambda: report([{"status": "Failed", "ended": days_ago(10, "%Y-%m-%dT%H:%M:%S")}]), False),
        ("successful_restore", lambda: report([{"status": "Successful", "ended": days_ago(10, "%Y-%m-%dT%H:%M:%S")}]), True),
        ("empty_report", lambda: report([]), False),
        ("drilled_empty_rows", lambda: [], False),
    ],
}


def run(name, key, body):
    out = load(name).transform(body)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]


class NotMeasuredIsNotGraded(unittest.TestCase):
    def test_no_evidence_reads_as_not_measured(self):
        for name, key in FILES:
            for case, body in NO_EVIDENCE + EXTRA_UNMEASURED.get(name, []):
                if case in MEASURED_WHEN_EMPTY.get(name, ()):
                    continue
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
