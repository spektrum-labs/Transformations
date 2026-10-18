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
    ("failedBackupJobsCount", "failedBackupJobsCount"),
    ("backupSuccessRatePercentage", "backupSuccessRatePercentage"),
    ("staleProtectionJobsCount", "staleProtectionJobsCount"),
    ("unprotectedResourcesCount", "unprotectedResourcesCount"),
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


def devices(*statuses):
    """getDeviceSummary records, one per backup_status (the counts read device status, not plans)."""
    return {"data": [{"device_id": "d" + str(i), "backup_status": s, "last_backup": "2026-10-06", "next_backup": "2026-10-08"}
                     for i, s in enumerate(statuses)]}


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
    "failedBackupJobsCount": [
        ("no_failures", lambda: devices("Success", "Success"), 0),
        ("two_failures", lambda: devices("Failure", "Failure", "Success"), 2),
    ],
    "backupSuccessRatePercentage": [
        ("all_failed", lambda: devices("Failure"), 0.0),
        ("three_of_four", lambda: devices("Success", "Success", "Success", "Failure"), 75.0),
    ],
    "staleProtectionJobsCount": [
        ("healthy", lambda: {"data": [{"device_id": "d1", "backup_status": "success", "last_backup": days_ago(1, "%Y-%m-%d %H:%M:%S"), "next_backup": days_ago(-1, "%Y-%m-%d %H:%M:%S")}]}, 0),
        ("one_failed", lambda: {"data": [{"device_id": "d1", "backup_status": "Failed", "last_backup": days_ago(3), "next_backup": days_ago(-1)}]}, 1),
    ],
    "unprotectedResourcesCount": [
        ("none_pending", lambda: plan(backup_pending_on=[], devices=["dev-a"]), 0),
        ("two_pending", lambda: plan(backup_pending_on=["dev-a", "dev-b"], devices=["dev-a", "dev-b", "dev-c"]), 2),
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
                    elif isinstance(expected, bool):
                        self.assertIs(value, expected)
                    else:
                        self.assertNotIsInstance(value, bool)
                        self.assertEqual(value, expected)
                    self.assertEqual(collection["status"], "success")
                    self.assertEqual(collection["errors"], [])

    def test_every_file_has_a_measured_case(self):
        for name, _key in FILES:
            self.assertTrue(MEASURED.get(name), name)


# The four count/rate files. Each lambda returns a body; every one of these proves nothing, so the
# count must be None with a dataCollection error -- never 0, which a "0 failed" requirement grades
# as a pass. Field names follow the IDrive getBackupPlan / getDeviceSummary bodies the transforms read.
COUNT_FIELDS = {
    "unprotectedResourcesCount": ("backup_pending_on",),
}
# Files that read getDeviceSummary records rather than backup plans.
DEVICE_FILES = ("failedBackupJobsCount", "backupSuccessRatePercentage", "staleProtectionJobsCount")


def plan_with(fields, value):
    return plan(**{f: value for f in fields})


def count_not_measured_cases(name):
    """(case, body) pairs that must read as not measured for one of the four files."""
    cases = [
        ("error", lambda: {"error": True, "statusCode": 500, "message": "internal error"}),
        ("error_string", lambda: {"error": "upstream timeout"}),
        ("error_flag_with_data", lambda: dict(plan_with(COUNT_FIELDS.get(name, ("backup_failed_on",)), []), error="partial read")),
        ("forbidden_403", lambda: {"statusCode": 403, "message": "Forbidden"}),
        ("forbidden_403_typed", lambda: {"error": {"type": "permission_error", "message": "Missing required scopes"}}),
        ("unauthorized_401", lambda: {"status_code": 401, "message": "invalid api key"}),
        ("empty_list", lambda: []),
        ("empty_dict", lambda: {}),
        ("empty_data_list", lambda: {"data": []}),
        ("no_list_in_body", lambda: {"message": "ok"}),
        ("data_null", lambda: {"data": None}),
        ("data_empty_string", lambda: {"data": ""}),
        ("unreadable_body", lambda: "<html>bad gateway</html>"),
    ]
    if name in ("failedBackupJobsCount", "backupSuccessRatePercentage"):
        cases = cases[:2] + cases[3:] + [
            ("missing_status", lambda: {"data": [{"device_id": "d1"}]}),
            ("no_device_has_a_status", lambda: {"data": [{"device_id": "d1", "backup_status": None}]}),
            ("one_device_unreadable", lambda: {"data": [{"device_id": "d1", "backup_status": "Success"}, {"device_id": "d2"}]}),
            ("truncated", lambda: dict(devices("Success"), paginationTruncated=True)),
        ]
        if name == "backupSuccessRatePercentage":
            cases = cases + [("no_attempts", lambda: devices("In Progress"))]
    elif name == "staleProtectionJobsCount":
        cases = cases[:2] + cases[3:] + [
            ("missing_count", lambda: {"data": [{"device_id": "d1"}]}),
            ("empty_count", lambda: {"data": [{"device_id": "d1", "backup_status": "", "last_backup": None, "next_backup": ""}]}),
            ("one_device_unreadable", lambda: {"data": [
                {"device_id": "d1", "backup_status": "success", "last_backup": days_ago(1), "next_backup": days_ago(-1)},
                {"device_id": "d2"},
            ]}),
        ]
    else:
        fields = COUNT_FIELDS[name]
        cases = cases + [
            ("missing_count", lambda: plan(is_enabled=True)),
            ("empty_count_null", lambda: plan_with(fields, None)),
            ("empty_count_string", lambda: plan_with(fields, "")),
            ("one_plan_missing_count", lambda: {"data": [
                dict({"id": "plan-1"}, **{f: [] for f in fields}),
                {"id": "plan-2", "is_enabled": True},
            ]}),
        ]
        if name == "backupSuccessRatePercentage":
            cases = cases + [
                ("no_attempts", lambda: plan(backup_applied_on=[], backup_failed_on=[], backup_pending_on=["dev-a"])),
                ("failed_list_missing", lambda: plan(backup_applied_on=["dev-a"])),
            ]
    return cases


COUNT_FILES = ["failedBackupJobsCount", "backupSuccessRatePercentage", "staleProtectionJobsCount", "unprotectedResourcesCount"]


class CountsFailClosed(unittest.TestCase):
    def assert_not_measured(self, name, case, body):
        with self.subTest(transform=name, body=case):
            value, collection = run(name, name, body)
            self.assertIsNone(value)
            self.assertEqual(collection["status"], "error")
            self.assertTrue(collection["errors"])
            self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))

    def test_no_evidence_counts_are_none_not_zero(self):
        for name in COUNT_FILES:
            for case, body in count_not_measured_cases(name):
                self.assert_not_measured(name, case, body())

    def test_zero_is_not_returned_on_an_error(self):
        for name in COUNT_FILES:
            for body in ({"error": True, "statusCode": 500, "message": "internal error"},
                         {"statusCode": 403, "message": "Forbidden"}):
                with self.subTest(transform=name, body=body):
                    value, collection = run(name, name, body)
                    self.assertNotEqual(value, 0)
                    self.assertIsNot(value, False)
                    self.assertIsNone(value)
                    self.assertEqual(collection["status"], "error")

    def test_real_zero_stays_zero(self):
        for name in COUNT_FILES:
            case, body, expected = MEASURED[name][0]
            with self.subTest(transform=name, body=case):
                value, collection = run(name, name, body())
                self.assertEqual(expected, 0)
                self.assertIsNotNone(value)
                self.assertNotIsInstance(value, bool)
                self.assertEqual(value, 0)
                self.assertEqual(collection["status"], "success")
                self.assertEqual(collection["errors"], [])

    def test_real_value_stays_its_value(self):
        for name in COUNT_FILES:
            case, body, expected = MEASURED[name][1]
            with self.subTest(transform=name, body=case):
                value, collection = run(name, name, body())
                self.assertNotIsInstance(value, bool)
                self.assertEqual(value, expected)
                self.assertEqual(collection["status"], "success")

    def test_real_zero_through_a_wrapper(self):
        # The enriched {"data", "validation"} input and an apiResponse wrapper must still measure.
        body = {"data": devices("Success"), "validation": {"status": "valid", "errors": [], "warnings": []}}
        self.assertEqual(run("failedBackupJobsCount", "failedBackupJobsCount", body)[0], 0)
        body = {"apiResponse": {"data": [{"id": "p", "backup_pending_on": ["dev-a"]}]}}
        self.assertEqual(run("unprotectedResourcesCount", "unprotectedResourcesCount", body)[0], 1)



# Counts derived from a read that measured nothing. In a not-measured result these must be None, not
# the 0 the loop started from, wherever they are published (inputSummary and the transformedResponse
# side fields). Record counts (plans or devices scanned) are real and stay as read.
DERIVED_COUNTS = {
    "failedBackupJobsCount": ("failedDevices",),
    "backupSuccessRatePercentage": ("successfulDevices", "failedDevices", "attempted"),
    "staleProtectionJobsCount": ("staleDevices",),
    "unprotectedResourcesCount": ("totalDevicesAssignedToPlans", "totalPendingDeviceIds"),
}

# Bodies whose counts were fully read even though the criterion is not measured.
COUNTS_WERE_READ = {("backupSuccessRatePercentage", "no_attempts"), ("backupSuccessRatePercentage", "no_device_has_a_status")}

VENDOR_TEXT = "vendor-detail-" + "x" * 300


class NotMeasuredDetail(unittest.TestCase):
    def test_derived_counts_are_none_when_not_measured(self):
        for name in COUNT_FILES:
            for case, body in count_not_measured_cases(name):
                if (name, case) in COUNTS_WERE_READ:
                    continue
                with self.subTest(transform=name, body=case):
                    out = load(name).transform(body())
                    summary = out["additionalInfo"]["transformation"]["inputSummary"]
                    result = out["transformedResponse"]
                    for field in DERIVED_COUNTS[name]:
                        if field in summary:
                            self.assertIsNone(summary[field], "inputSummary." + field)
                        if field in result and field != name:
                            self.assertIsNone(result[field], "transformedResponse." + field)

    def test_derived_counts_stay_as_read_when_measured(self):
        for name in COUNT_FILES:
            for case, body, _expected in MEASURED[name]:
                with self.subTest(transform=name, body=case):
                    summary = load(name).transform(body())["additionalInfo"]["transformation"]["inputSummary"]
                    for field in DERIVED_COUNTS[name]:
                        if field in summary:
                            self.assertIsInstance(summary[field], int)
                            self.assertNotIsInstance(summary[field], bool)

    def test_error_reason_does_not_echo_vendor_text(self):
        for name in COUNT_FILES:
            for body in ({"error": VENDOR_TEXT}, {"error": {"message": VENDOR_TEXT}},
                         {"errors": [VENDOR_TEXT]}, {"Error": {"Code": "AccessDenied", "Message": VENDOR_TEXT}}):
                with self.subTest(transform=name, body=str(body)[:40]):
                    out = load(name).transform(body)
                    self.assertIsNone(out["transformedResponse"][name])
                    self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                    self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
                    self.assertNotIn("vendor-detail", json.dumps(out))


if __name__ == "__main__":
    unittest.main()
