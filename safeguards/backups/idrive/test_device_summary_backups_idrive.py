"""IDrive backup counts read from getDeviceSummary (GET /api/msp/device/summary).

The getBackupPlan body carries no per-device outcome lists (no backup_failed_on / applied_on /
pending_on), so failedBackupJobsCount and backupSuccessRatePercentage are measured from each
device's backup_status ("Success" / "Failure"; the API docs also list "Failed"), and
staleProtectionJobsCount counts a "Failure" or "Not protected" device as stale.

Rules kept from the earlier fixes: an error, empty list, missing field or truncated read gives
None with a dataCollection error (Not evaluated); a real zero stays zero; when no device has a
Success or Failure status, the rate is None. Synthetic data only.
"""
import copy
import importlib.util
import os
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("ds_idrive_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def iso(days):
    return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def device(n, status="Success", last=-1, nxt=1, **extra):
    """One getDeviceSummary record with the field set the API returns (made-up values)."""
    record = {
        "os": "Windows", "version": "1.0.0", "name": "host-" + str(n), "status": "online",
        "device_id": "dev-" + str(n), "company_id": 1001, "custom_tag": "", "group_name": "Default",
        "backup_status": status,
        "last_backup": iso(last) if last is not None else None,
        "next_backup": iso(nxt) if nxt is not None else None,
        "backup_failure_reason": "NA", "next_scheduled_backupset_name": "Default",
        "backup_sets": {"Default": {"id": 1, "name": "Default"}}, "metadata": {},
    }
    record.update(extra)
    return record


def sample():
    """Five devices, one failed (last successful backup 6 days ago), four succeeded."""
    return [device(1), device(2), device(3, status="Failure", last=-6, nxt=1), device(4), device(5)]


def plan_body():
    """A getBackupPlan record as the API returns it: no per-device outcome lists."""
    return [{"id": 1, "name": "plan-1", "backup_set": "Default", "is_enabled": True, "exclude_partial": False,
             "exclude_system": True, "exclude_hidden": True,
             "backup_details": {"what_to_backup": "FILES_AND_FOLDERS", "where_to_backup": "CLOUD", "items_to_backup": []},
             "cdp_enabled": False,
             "schedule_info": {"email": "", "start_missed_backup": True, "days": ["MON"], "frequency_type": "DAILY",
                               "time": "02:00", "cutoff_time": "", "send_email_notification": "ON_FAILURE"},
             "devices": []}]


def run(name, body):
    out = load(name).transform(body)
    return out["transformedResponse"][name], out["additionalInfo"]["dataCollection"]


COUNTS = ("failedBackupJobsCount", "backupSuccessRatePercentage")


class SampleIsMeasured(unittest.TestCase):
    def test_five_device_sample(self):
        for body in (sample(), {"data": sample()}, {"apiResponse": {"data": sample()}}):
            with self.subTest(shape=type(body).__name__):
                value, dc = run("failedBackupJobsCount", body)
                self.assertEqual(value, 1)
                self.assertNotIsInstance(value, bool)
                self.assertEqual(dc["status"], "success")
                value, dc = run("backupSuccessRatePercentage", body)
                self.assertEqual(value, 80.0)
                self.assertEqual(dc["status"], "success")
                value, dc = run("staleProtectionJobsCount", body)
                self.assertEqual(value, 1)
                self.assertEqual(dc["status"], "success")

    def test_real_zero_stays_zero(self):
        body = [device(1), device(2)]
        self.assertEqual(run("failedBackupJobsCount", body), (0, {"status": "success", "errors": []}))
        self.assertEqual(run("backupSuccessRatePercentage", body)[0], 100.0)
        self.assertEqual(run("staleProtectionJobsCount", body)[0], 0)

    def test_all_failed_rate_is_zero_not_none(self):
        value, dc = run("backupSuccessRatePercentage", [device(1, status="Failure"), device(2, status="Failed")])
        self.assertEqual(value, 0.0)
        self.assertEqual(dc["status"], "success")
        self.assertEqual(run("failedBackupJobsCount", [device(1, status="Failure"), device(2, status="Failed")])[0], 2)

    def test_status_is_case_insensitive(self):
        self.assertEqual(run("failedBackupJobsCount", [device(1, status="failure"), device(2, status="SUCCESS")])[0], 1)
        self.assertEqual(run("backupSuccessRatePercentage", [device(1, status="failure"), device(2, status="SUCCESS")])[0], 50.0)

    def test_in_progress_is_not_an_attempt(self):
        body = [device(1, status="In Progress"), device(2), device(3, status="Failure")]
        self.assertEqual(run("backupSuccessRatePercentage", body)[0], 50.0)
        self.assertEqual(run("failedBackupJobsCount", body)[0], 1)


class StaleCountsFailureAsUnhealthy(unittest.TestCase):
    def test_failure_with_future_schedule_is_stale(self):
        self.assertEqual(run("staleProtectionJobsCount", [device(1, status="Failure", last=-6, nxt=1)])[0], 1)

    def test_not_protected_is_stale(self):
        self.assertEqual(run("staleProtectionJobsCount", [device(1, status="Not protected", last=None, nxt=1)])[0], 1)

    def test_lower_case_failure_is_stale(self):
        self.assertEqual(run("staleProtectionJobsCount", [device(1, status="failure", nxt=1)])[0], 1)

    def test_success_with_future_schedule_is_healthy(self):
        self.assertEqual(run("staleProtectionJobsCount", [device(1), device(2)])[0], 0)


def not_measured_bodies():
    no_status = sample()
    for d in no_status:
        d["backup_status"] = None
    missing_key = sample()
    del missing_key[2]["backup_status"]
    return [
        ("error_envelope", {"error": True, "statusCode": 424, "status": "Error", "message": "x"}),
        ("http_401", {"statusCode": 401, "message": "invalid api key"}),
        ("error_with_data", {"data": sample(), "error": "partial read"}),
        ("empty_list", []),
        ("empty_dict", {}),
        ("data_empty", {"data": []}),
        ("data_null", {"data": None}),
        ("data_dict", {"data": {"total": 5}}),
        ("none", None),
        ("unreadable", "<html>bad gateway</html>"),
        ("truncated", {"data": sample(), "paginationTruncated": True}),
        ("truncated_wrapped", {"apiResponse": {"data": sample(), "paginationTruncated": True}}),
        ("item_errors", {"data": sample(), "itemErrors": [{"index": 9}]}),
        ("one_record_missing_status", missing_key),
        ("one_record_not_an_object", sample() + ["dev-9"]),
        ("no_device_has_a_status", no_status),
        ("plan_body", plan_body()),
    ]


class NotMeasuredIsNone(unittest.TestCase):
    def test_counts_are_none_with_a_collection_error(self):
        for name in COUNTS:
            for case, body in not_measured_bodies():
                with self.subTest(transform=name, body=case):
                    value, dc = run(name, copy.deepcopy(body))
                    self.assertIsNone(value)
                    self.assertEqual(dc["status"], "error")
                    self.assertTrue(dc["errors"])

    def test_only_in_progress_gives_no_rate(self):
        value, dc = run("backupSuccessRatePercentage", [device(1, status="In Progress")])
        self.assertIsNone(value)
        self.assertEqual(dc["status"], "error")

    def test_stale_on_truncated_or_plan_body_is_none(self):
        for case, body in (("truncated", {"data": sample(), "paginationTruncated": True}), ("plan_body", plan_body())):
            with self.subTest(body=case):
                value, dc = run("staleProtectionJobsCount", body)
                self.assertIsNone(value)
                self.assertEqual(dc["status"], "error")


if __name__ == "__main__":
    unittest.main()
