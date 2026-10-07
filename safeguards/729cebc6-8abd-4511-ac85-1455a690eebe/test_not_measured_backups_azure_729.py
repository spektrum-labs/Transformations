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
    # arg_rows_empty: zero Resource Graph rows is RBAC-ambiguous and is not measured.
    # See CONTRIBUTING.md, "Azure Resource Graph: zero rows is not a proven empty set".
    "isbackupenabled": [("data_without_rows", lambda: {"data": {"columns": []}}),
                        ("arg_rows_empty", lambda: {"data": {"rows": []}})],
    "is_backup_types_scheduled": [("data_without_rows", lambda: {"data": {"columns": []}}),
                                  ("arg_rows_empty", lambda: {"data": {"rows": []}})],
    "is_backup_tested": [("arg_rows_empty", lambda: {"data": {"columns": [{"name": "name"}], "rows": []}})],
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
        # A row that CAME BACK and reports zero protected items is a measured False: that
        # vault was read. Only the empty rows array is ambiguous.
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


SAFEGUARDS = os.path.dirname(HERE)
AZURE = os.path.join(SAFEGUARDS, "backups", "azure")

# Every Azure Resource Graph reader in the tree, both the 729 set and its drifted copies
# under backups/azure. The census is asserted complete by
# test_no_resource_graph_reader_is_missing_from_this_list below, so a new one cannot be
# added outside the rule without this file failing.
ARG_ROWS_READERS = [
    ("729/confirmedlicensepurchased", "confirmedLicensePurchased", os.path.join(HERE, "confirmedlicensepurchased.py")),
    ("729/is_backup_encrypted", "isBackupEncrypted", os.path.join(HERE, "is_backup_encrypted.py")),
    ("729/is_backup_immutable", "isBackupImmutable", os.path.join(HERE, "is_backup_immutable.py")),
    ("729/is_backup_tested", "isBackupTested", os.path.join(HERE, "is_backup_tested.py")),
    ("729/is_backup_types_scheduled", "isBackupTypesScheduled", os.path.join(HERE, "is_backup_types_scheduled.py")),
    ("729/isbackupenabled", "isBackupEnabled", os.path.join(HERE, "isbackupenabled.py")),
    ("azure/backupfrequency", "backupFrequency", os.path.join(AZURE, "backupfrequency.py")),
    ("azure/is_backup_encrypted", "isBackupEncrypted", os.path.join(AZURE, "is_backup_encrypted.py")),
    ("azure/is_backup_immutable", "isBackupImmutable", os.path.join(AZURE, "is_backup_immutable.py")),
    ("azure/is_backup_tested", "isBackupTested", os.path.join(AZURE, "is_backup_tested.py")),
    ("azure/is_backup_types_scheduled", "isBackupTypesScheduled", os.path.join(AZURE, "is_backup_types_scheduled.py")),
    ("azure/isbackupenabled", "isBackupEnabled", os.path.join(AZURE, "isbackupenabled.py")),
]


def load_path(label, path):
    spec = importlib.util.spec_from_file_location("arg_rows_" + label, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ZeroResourceGraphRowsIsNotMeasured(unittest.TestCase):
    """One rule for every Resource Graph reader here, so the next reader cannot differ.

    Resource Graph is RBAC-scoped. A wholly unreadable scope answers 403, but a PARTIALLY
    readable one answers 200 carrying only the readable subset and, in Microsoft's words,
    "without any indication that the result might be partial"
    (learn.microsoft.com/azure/governance/resource-graph/overview#permissions-in-azure-resource-graph).
    Zero rows is therefore equally "there are none" and "the vaults are in a subscription
    this principal cannot read", so it may not be reported as a measured answer.
    """

    VALIDATION = {"status": "passed", "errors": [], "warnings": []}

    EMPTY_ROWS = [
        ("flat", {"columns": [{"name": "result"}], "rows": [], "totalRecords": 0}),
        ("nested", {"data": {"columns": [{"name": "result"}], "rows": [], "totalRecords": 0}}),
        ("rows_only", {"data": {"rows": []}}),
    ]

    def test_every_resource_graph_reader_treats_zero_rows_alike(self):
        for label, key, path in ARG_ROWS_READERS:
            module = load_path(label, path)
            for shape, body in self.EMPTY_ROWS:
                with self.subTest(transform=label, shape=shape):
                    out = module.transform({"data": body, "validation": self.VALIDATION})
                    collection = out["additionalInfo"]["dataCollection"]
                    self.assertIsNone(out["transformedResponse"][key],
                                      label + " reported a measured answer from zero Resource Graph rows")
                    self.assertEqual(collection["status"], "error")
                    self.assertTrue(collection["errors"])

    def test_the_rule_does_not_leak_to_arm_list_endpoints(self):
        """An ARM list 403s on an unreadable scope, so ITS empty list is a proven empty set."""
        module = load_path("is_backup_tested", os.path.join(HERE, "is_backup_tested.py"))
        out = module.transform({"data": {"value": []}, "validation": self.VALIDATION})
        self.assertIs(out["transformedResponse"]["isBackupTested"], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_no_resource_graph_reader_is_missing_from_this_list(self):
        """The rule is only as good as the census, so the census is asserted, not sampled.

        A transform is a Resource Graph reader when it names Resource Graph AND reads a
        "rows" key. That pair is what distinguishes the Azure files from Datto BCDR, whose
        own envelope also carries data.rows, and from the EPP checks, which merely list
        "rows" among candidate container keys. Any new one must be added here, which forces
        whoever adds it to decide what it does with zero rows.
        """
        listed = set()
        for _, _, path in ARG_ROWS_READERS:
            listed.add(os.path.realpath(path))
        found = set()
        for folder, _, names in os.walk(SAFEGUARDS):
            for name in names:
                if not name.endswith(".py") or name.startswith("test_") or name == "__init__.py":
                    continue
                if os.path.basename(folder) == "schemas":
                    continue
                path = os.path.join(folder, name)
                with open(path, encoding="utf-8") as handle:
                    source = handle.read()
                if '"rows"' in source and "esource Graph" in source:
                    found.add(os.path.realpath(path))
        missing = sorted(os.path.relpath(p, SAFEGUARDS) for p in found - listed)
        self.assertEqual(missing, [], "Resource Graph readers not covered by the zero-rows rule: "
                                      + ", ".join(missing))
        stale = sorted(os.path.relpath(p, SAFEGUARDS) for p in listed - found)
        self.assertEqual(stale, [], "listed but no longer a Resource Graph reader: " + ", ".join(stale))

    def test_a_row_that_came_back_still_answers(self):
        """Only the EMPTY rows array is ambiguous; a row that was read is evidence."""
        module = load_path("is_backup_types_scheduled", os.path.join(HERE, "is_backup_types_scheduled.py"))
        out = module.transform({"data": {"data": {"rows": [{"properties": {"protectedItemsCount": 0}}]}},
                                "validation": self.VALIDATION})
        self.assertIs(out["transformedResponse"]["isBackupTypesScheduled"], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")


if __name__ == "__main__":
    unittest.main()
