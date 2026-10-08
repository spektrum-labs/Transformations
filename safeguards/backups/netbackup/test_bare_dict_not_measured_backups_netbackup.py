"""The boolean NetBackup checks return the full envelope, with "not measured" read from the value.

These transforms used to return a bare {key: False, "reason": ...} with no additionalInfo, so Token-Service graded
every unreadable body as a FAIL. Each body in UNMEASURED proves nothing about the estate: the criterion must be None
AND dataCollection.status "error". A well-formed body that says off stays False with status "success", and a passing
body stays True. Synthetic data only.
"""
import importlib.util
import os
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("bdnm_" + name, os.path.join(HERE, name + ".py"))
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


def ts(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def job(i, status=0, days=1):
    return {"type": "job", "id": str(i), "attributes": {"jobId": i, "jobType": "BACKUP", "state": "DONE",
                                                        "status": status, "endTime": ts(days)}}


def jobs(items, nxt=None):
    d = {"data": items, "meta": {"pagination": {"limit": 100}}}
    if nxt:
        d["meta"]["pagination"]["next"] = nxt
    return d


def status(**over):
    detail = {"ssoEnabled": {"currentConfigState": True}, "mfaEnforced": {"currentConfigState": True},
              "backupAnomalyDetection": {"currentConfigState": 2},
              "isImmutableBackupStorageConfigured": {"currentConfigState": True, "totalImmutableBackupStorages": 3,
                                                     "totalActiveBackupStorages": 3},
              "clientPercentageWithLatestNbuVersion": {"currentConfigState": 100, "totalHosts": 40}}
    for k, v in over.items():
        if v is None:
            detail.pop(k)
        else:
            detail[k] = v
    return {"data": {"type": "securityStatus", "id": "1", "attributes": {"securitySettingsDetail": detail}}}


UNMEASURED = [
    ("empty_dict", lambda: {}),
    ("empty_list", lambda: []),
    ("not_available", lambda: {"status": "Not Available"}),
    ("refusal_401", lambda: {"errorCode": 401, "errorMessage": "Unauthorized"}),
    ("poisoned", lambda: Poisoned()),
]

FILES = {
    "isbackupclientversioncurrent": "isBackupClientVersionCurrent",
    "isbackupenabled": "isBackupEnabled",
    "isbackupimmutable": "isBackupImmutable",
    "ismfaenforcedforusers": "isMFAEnforcedForUsers",
    "isssoenabled": "isSSOEnabled",
    "isransomwaredetectionenabled": "isRansomwareDetectionEnabled",
}

# (file, body that is present but cannot answer the check) -> None + "error"
MISSING = [
    ("isbackupclientversioncurrent", status(clientPercentageWithLatestNbuVersion=None)),
    ("isbackupclientversioncurrent", status(clientPercentageWithLatestNbuVersion={"currentConfigState": 100})),
    ("isbackupenabled", jobs([{"type": "job"}])),
    ("isbackupenabled", jobs([job(1, status=2, days=1)], nxt="page2")),
    ("isbackupimmutable", status(isImmutableBackupStorageConfigured={"currentConfigState": True})),
    ("ismfaenforcedforusers", status(mfaEnforced={"currentConfigState": None})),
    ("isssoenabled", status(ssoEnabled=None)),
    ("isransomwaredetectionenabled", status(backupAnomalyDetection={"currentConfigState": "unknown"})),
]

# (file, well-formed body that says off) -> False + "success"
MEASURED_OFF = [
    ("isbackupclientversioncurrent", status(clientPercentageWithLatestNbuVersion={"currentConfigState": 87.5, "totalHosts": 40})),
    ("isbackupclientversioncurrent", status(clientPercentageWithLatestNbuVersion={"currentConfigState": 100, "totalHosts": 0})),
    ("isbackupenabled", jobs([job(1, status=2, days=1), job(2, status=0, days=10)])),
    ("isbackupenabled", jobs([])),
    ("isbackupimmutable", status(isImmutableBackupStorageConfigured={"currentConfigState": True, "totalImmutableBackupStorages": 1, "totalActiveBackupStorages": 3})),
    ("ismfaenforcedforusers", status(mfaEnforced={"currentConfigState": False})),
    ("isssoenabled", status(ssoEnabled={"currentConfigState": False})),
    ("isransomwaredetectionenabled", status(backupAnomalyDetection={"currentConfigState": 1})),
    ("isransomwaredetectionenabled", status(backupAnomalyDetection={"currentConfigState": 3})),
]

# (file, passing body) -> True + "success"
MEASURED_ON = [
    ("isbackupclientversioncurrent", status()),
    ("isbackupenabled", jobs([job(1, status=0, days=1)])),
    ("isbackupimmutable", status()),
    ("ismfaenforcedforusers", status()),
    ("isssoenabled", status()),
    ("isransomwaredetectionenabled", status()),
]


class BareDictBecomesEnvelope(unittest.TestCase):
    def check(self, name, body, value, state):
        key = FILES[name]
        out = load(name).transform(body)
        self.assertIn("transformedResponse", out)
        inner = out["transformedResponse"]
        self.assertIs(inner[key], value)
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], state)
        if state == "error":
            self.assertTrue(collection["errors"])
            self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))
        else:
            self.assertEqual(collection["errors"], [])
        self.assertTrue(inner.get("reason"))

    def test_unreadable_bodies_are_not_measured(self):
        for name in FILES:
            for case, body in UNMEASURED:
                with self.subTest(transform=name, body=case):
                    self.check(name, body(), None, "error")

    def test_present_but_unanswerable_is_not_measured(self):
        for name, body in MISSING:
            with self.subTest(transform=name, body=body):
                self.check(name, body, None, "error")

    def test_measured_off_stays_false(self):
        for name, body in MEASURED_OFF:
            with self.subTest(transform=name, body=body):
                self.check(name, body, False, "success")

    def test_measured_on_stays_true(self):
        for name, body in MEASURED_ON:
            with self.subTest(transform=name, body=body):
                self.check(name, body, True, "success")


if __name__ == "__main__":
    unittest.main()
