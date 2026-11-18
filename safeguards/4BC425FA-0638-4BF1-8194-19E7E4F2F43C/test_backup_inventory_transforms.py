"""Backup checks that read the AWS backup inventory (getBackupInventory) instead of the newest backup.

The fixture is the inventory Integration-Service's collector produced for a synthetic account (made-up
account number and names): a graph database whose plan's daily run was dropped while its own continuous
backups stayed current, a volume whose only snapshot is two weeks old and shared publicly, and a table
with no backup at all. The getBackups-based checks passed an account shaped like this; these must not.
"""
import copy
import importlib.util
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
INVENTORY = json.loads('''{"accountId": "111122223333", "awsBackup": {"jobStates35d": {"COMPLETED": 6}, "plans": [{"assignedResources": 1, "lastExecutionAt": null, "name": "graph-daily", "planId": "plan-1", "region": "us-east-1", "rules": [{"completionWindowMinutes": 180, "continuous": false, "copyTo": [], "deleteAfterDays": 35, "evaluated": true, "name": "daily", "ruleId": "rule-daily", "schedule": "cron(0 5 ? * * *)", "startWindowMinutes": 60, "targetVault": "graph-vault", "timezone": "UTC"}, {"completionWindowMinutes": null, "continuous": false, "copyTo": [], "deleteAfterDays": null, "evaluated": true, "name": "weekly", "ruleId": "rule-weekly", "schedule": "cron(0 5 ? * SUN *)", "startWindowMinutes": 60, "targetVault": "graph-vault", "timezone": "UTC"}], "selections": [], "versionId": "v2"}]}, "collectedAt": "2026-11-16T23:40:00Z", "failedLatestAttempts": [], "missedRuns": [{"arn": "arn:aws:rds:us-east-1:111122223333:cluster:graph-prod", "expectedAt": "2026-11-16T05:00:00Z", "jobState": null, "planId": "plan-1", "planName": "graph-daily", "region": "us-east-1", "ruleName": "daily", "status": "missed", "type": "AWS::Neptune::DBCluster"}], "publicShares": [{"region": "us-east-1", "resourceId": "vol-0a1b2c3d", "resourceType": "AWS::EC2::Snapshot", "sharedWith": "all", "snapshotId": "snap-0pub1ic"}], "resources": [{"arn": "arn:aws:dynamodb:us-east-1:111122223333:table/scratch", "backupCapable": true, "id": "scratch", "lastGoodAt": null, "name": "scratch", "publicShares": [], "region": "us-east-1", "service": "dynamodb", "type": "AWS::DynamoDB::Table"}, {"arn": "arn:aws:ec2:us-east-1:111122223333:volume/vol-0a1b2c3d", "backupCapable": true, "id": "vol-0a1b2c3d", "lastGoodAt": "2026-11-01T01:00:00Z", "name": "vol-0a1b2c3d", "publicShares": [{"resourceId": "vol-0a1b2c3d", "sharedWith": "all", "snapshotId": "snap-0pub1ic"}], "region": "us-east-1", "service": "ec2", "type": "AWS::EC2::Volume"}, {"arn": "arn:aws:rds:us-east-1:111122223333:cluster:graph-prod", "backupCapable": true, "id": "graph-prod", "lastGoodAt": "2026-11-16T23:35:00Z", "name": "graph-prod", "publicShares": [], "region": "us-east-1", "service": "neptune", "type": "AWS::Neptune::DBCluster"}], "schemaVersion": "aws-backup-inventory/1", "scope": {"complete": true, "errors": [], "missingPermissions": [], "regionsScanned": ["us-east-1"], "regionsUnreachable": {}, "timedOut": [], "truncated": []}}''')
KEYS = {
    "missedscheduledbackups": "missedScheduledBackups",
    "backupcoveragepercentage": "backupCoveragePercentage",
    "lastsuccessfulbackupage_inventory": "lastSuccessfulBackupAge",
    "backupjobfailures": "backupJobFailures",
    "publicbackupsharecount": "publicBackupShareCount",
    "isbackupinventorycomplete": "isBackupInventoryComplete",
}


def load(name):
    spec = importlib.util.spec_from_file_location("inv_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = {name: load(name) for name in KEYS}


def value(name, body):
    out = MODULES[name].transform(body)
    return out["transformedResponse"][KEYS[name]], out["additionalInfo"]


def inventory(**changes):
    inv = copy.deepcopy(INVENTORY)
    for key, val in changes.items():
        inv[key] = val
    return inv


class ReplayOfADroppedRun(unittest.TestCase):

    def test_the_dropped_run_fails_the_schedule_check(self):
        got, info = value("missedscheduledbackups", inventory())
        self.assertEqual(got, 1)
        self.assertIn("graph-prod", info["evaluation"]["failReasons"][0])
        self.assertIn("2026-11-16T05:00:00Z", info["evaluation"]["failReasons"][0])

    def test_age_is_the_stalest_resource_not_the_freshest(self):
        got, info = value("lastsuccessfulbackupage_inventory", inventory())
        self.assertEqual(got, 382)  # the volume's 1 Nov snapshot, not the database's 23:35 point
        self.assertIn("vol-0a1b2c3d", info["transformation"]["inputSummary"]["stalest"])

    def test_coverage_counts_unprotected_and_stale_resources(self):
        got, info = value("backupcoveragepercentage", inventory())
        self.assertEqual(got, 33.33)
        self.assertEqual(info["transformation"]["inputSummary"]["uncovered"], 2)
        self.assertTrue(any("no backup of any kind" in r for r in info["evaluation"]["failReasons"]))

    def test_public_snapshot_is_counted(self):
        self.assertEqual(value("publicbackupsharecount", inventory())[0], 1)

    def test_no_failed_latest_job_and_a_complete_inventory(self):
        self.assertEqual(value("backupjobfailures", inventory())[0], 0)
        self.assertIs(value("isbackupinventorycomplete", inventory())[0], True)


class Windows(unittest.TestCase):

    def test_a_miss_older_than_48_hours_no_longer_counts(self):
        self.assertEqual(value("missedscheduledbackups", inventory(collectedAt="2026-11-18T06:00:00Z"))[0], 0)

    def test_a_failed_run_counts(self):
        runs = [dict(INVENTORY["missedRuns"][0], status="failed", jobState="FAILED")]
        got, info = value("missedscheduledbackups", inventory(missedRuns=runs))
        self.assertEqual(got, 1)
        self.assertIn("FAILED", info["evaluation"]["failReasons"][0])

    def test_no_misses_is_zero_with_a_pass_reason(self):
        got, info = value("missedscheduledbackups", inventory(missedRuns=[]))
        self.assertEqual(got, 0)
        self.assertTrue(info["evaluation"]["passReasons"])

    def test_failing_latest_job_is_counted(self):
        failing = [{"arn": "arn:aws:ec2:us-east-1:111122223333:volume/vol-0a1b2c3d", "type": "AWS::EC2::Volume",
                    "region": "us-east-1", "job": {"state": "FAILED", "createdAt": "2026-11-16T05:00:00Z"}}]
        self.assertEqual(value("backupjobfailures", inventory(failedLatestAttempts=failing))[0], 1)


class NotEvaluatedWhenTheEvidenceIsMissing(unittest.TestCase):

    def assert_not_evaluated(self, name, body):
        got, info = value(name, body)
        self.assertIsNone(got, name)
        self.assertEqual(info["dataCollection"]["status"], "error", name)
        self.assertTrue(info["dataCollection"]["errors"], name)

    def test_bodies_that_prove_nothing(self):
        bodies = [None, {}, [], "", "not json", b"{}", {"apiResponse": {}},
                  {"error": True, "status": "error", "statusCode": 403, "message": "The AWS credentials were refused"},
                  {"schemaVersion": "something-else/1", "resources": [], "scope": {}},
                  {"schemaVersion": "aws-backup-inventory/1"}]
        for name in KEYS:
            for body in bodies:
                self.assert_not_evaluated(name, body)

    def test_refused_job_history_is_not_a_zero(self):
        scope = dict(INVENTORY["scope"], missingPermissions=[{"action": "backup:ListBackupJobs",
                                                              "regions": ["us-east-1"]}], complete=False)
        self.assert_not_evaluated("missedscheduledbackups", inventory(scope=scope, missedRuns=[]))
        self.assert_not_evaluated("backupjobfailures", inventory(scope=scope))
        got, info = value("isbackupinventorycomplete", inventory(scope=scope))
        self.assertIs(got, False)
        self.assertIn("backup:ListBackupJobs", info["evaluation"]["failReasons"][0])

    def test_refused_snapshot_reads_are_not_a_zero(self):
        scope = dict(INVENTORY["scope"], missingPermissions=[{"action": "ec2:DescribeSnapshots",
                                                              "regions": ["us-east-1"]}], complete=False)
        self.assert_not_evaluated("publicbackupsharecount", inventory(scope=scope, publicShares=[]))

    def test_an_account_with_nothing_to_back_up_has_no_coverage_value(self):
        self.assert_not_evaluated("backupcoveragepercentage", inventory(resources=[]))
        self.assert_not_evaluated("lastsuccessfulbackupage_inventory", inventory(resources=[]))

    def test_an_unreachable_region_makes_the_inventory_incomplete(self):
        scope = dict(INVENTORY["scope"], regionsUnreachable={"ap-east-1": "OptInRequired"})
        got, info = value("isbackupinventorycomplete", inventory(scope=scope))
        self.assertIs(got, False)
        self.assertIn("ap-east-1", " ".join(info["evaluation"]["failReasons"]))


class Wrapping(unittest.TestCase):

    def test_the_engine_wrapper_and_json_text_are_read(self):
        for body in ({"apiResponse": inventory()}, {"response": {"result": inventory()}}, json.dumps(inventory()),
                     {"data": inventory(), "validation": {}}):
            self.assertEqual(value("missedscheduledbackups", body)[0], 1)


if __name__ == "__main__":
    unittest.main()
