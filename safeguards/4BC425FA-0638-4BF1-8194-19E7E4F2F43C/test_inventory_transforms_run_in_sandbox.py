"""The AWS backup inventory transforms must run in the sandbox production uses, not only as plain Python.

Production compiles each transform with RestrictedPython and gives it a reduced set of builtins.
`bytearray` is not one of them, so a transform that names it raises NameError on every call; its
`except Exception` turns that into "could not read the inventory" and the check is never evaluated.
Each transform below must give the same answer in the sandbox mirror as it does when imported.
Synthetic data only.
"""
import copy
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "..", "..", "tools")

NAMES = ["backupcoveragepercentage", "backupjobfailures", "isbackupinventorycomplete",
         "lastsuccessfulbackupage_inventory", "missedscheduledbackups", "publicbackupsharecount"]

INVENTORY = {
    "schemaVersion": "aws-backup-inventory/1",
    "collectedAt": "2026-01-02T12:00:00Z",
    "accountId": "111122223333",
    "partition": "aws",
    "status": "success",
    "scope": {
        "homeRegion": "us-east-1", "regionsDiscovered": ["us-east-1"], "regionsRequested": None,
        "regionsScanned": ["us-east-1"], "regionsUnreachable": {}, "regionsIgnored": [],
        "servicesUnavailable": {}, "missingPermissions": [], "errors": [], "truncated": [],
        "timedOut": [], "complete": True,
    },
    "awsBackup": {"plans": [], "jobStates35d": {}},
    "resources": [{
        "arn": "arn:aws:rds:us-east-1:111122223333:db:example-db", "id": "example-db", "name": "example-db",
        "type": "AWS::RDS::DBInstance", "service": "rds", "region": "us-east-1", "accountId": "111122223333",
        "backupCapable": True, "mechanisms": ["rds-automated"], "lastGoodAt": "2026-01-02T06:00:00Z",
    }],
    "missedRuns": [],
    "failedLatestAttempts": [],
    "publicShares": [],
    "notes": {},
    "summary": {},
}


def plain(name):
    spec = importlib.util.spec_from_file_location("inv_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(name):
    sys.path.insert(0, TOOLS)
    try:
        import restricted_sandbox
    finally:
        sys.path.remove(TOOLS)
    with open(os.path.join(HERE, name + ".py")) as handle:
        return restricted_sandbox.load(handle.read())["transform"]


def comparable(result):
    result = copy.deepcopy(result)
    result.get("additionalInfo", {}).get("metadata", {}).pop("evaluatedAt", None)
    return json.dumps(result, sort_keys=True, default=str)


class InventoryTransformsRunInSandbox(unittest.TestCase):
    def test_each_transform_answers_the_same_in_the_sandbox(self):
        for name in NAMES:
            for body in (INVENTORY, json.dumps(INVENTORY), json.dumps(INVENTORY).encode("utf-8")):
                with self.subTest(name=name, kind=type(body).__name__):
                    boxed = sandboxed(name)(copy.deepcopy(body))
                    self.assertNotIn("could not read the inventory", json.dumps(boxed))
                    self.assertEqual(comparable(boxed), comparable(plain(name)(copy.deepcopy(body))))

    def test_last_successful_backup_age_is_measured_in_the_sandbox(self):
        out = sandboxed("lastsuccessfulbackupage_inventory")(copy.deepcopy(INVENTORY))
        self.assertEqual(out["transformedResponse"]["lastSuccessfulBackupAge"], 6)


if __name__ == "__main__":
    unittest.main()
