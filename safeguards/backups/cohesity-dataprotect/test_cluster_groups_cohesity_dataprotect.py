"""Cohesity DataProtect: protection groups read per cluster (clusterGroups), beside the tenant-wide shape.

Helios' tenant-wide list never carries a group's last run, so the definition fans the per-cluster list
out over the clusters registered in Helios: one body per cluster under clusterGroups, in the clusters'
order, with an error record in the slot of a cluster Helios could not reach. A cluster Helios reports as
not connected is out of reach by definition and does not make the read partial; a connected cluster
whose read failed does, and a count from part of the estate is not a total. Synthetic data only.
"""
import copy
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
LOADED = {}


def load(name):
    if name not in LOADED:
        spec = importlib.util.spec_from_file_location("cohesity_cg_" + name, os.path.join(HERE, name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        LOADED[name] = module
    return LOADED[name]


def group(cluster, n, status="Succeeded", sla=False, start=None, active=True, run=True):
    g = {"id": "%d:1:%d" % (cluster, n), "name": "pg-%d-%d" % (cluster, n), "policyId": "%d:1:9" % cluster,
         "isActive": active, "isPaused": False}
    if run:
        g["lastRun"] = {"localBackupInfo": {"status": status, "isSlaViolated": sla,
                                            "startTimeUsecs": start if start is not None else 4102444800000000}}
    return g


def policy(cluster, lock="Compliance", schedule=True):
    reg = {"retention": {"dataLockConfig": {"mode": lock, "duration": 2, "unit": "Weeks"}} if lock else {}}
    if schedule:
        reg["incremental"] = {"schedule": {"unit": "Days"}}
    return {"id": "%d:1:9" % cluster, "name": "Gold-%d" % cluster, "backupPolicy": {"regular": reg}}


CLUSTERS = {"cohesityClusters": [{"clusterId": 1, "clusterName": "alpha", "isConnectedToHelios": True},
                                 {"clusterId": 2, "clusterName": "beta", "isConnectedToHelios": False},
                                 {"clusterId": 3, "clusterName": "gamma", "isConnectedToHelios": True}]}
DEAD = {"error": True, "statusCode": 502, "item": 2, "errorType": "vendorError"}


def body(slots, policies=None, **extra):
    out = {"clusters": copy.deepcopy(CLUSTERS), "clusterGroups": copy.deepcopy(slots),
           "iterateStats": {"clusterGroups": {"itemsTotal": 3, "itemsProcessed": 3, "itemErrors": 1, "iterateTruncated": False}},
           "itemErrors": 1}
    if policies is not None:
        out["policies"] = copy.deepcopy(policies)
    out.update(extra)
    return {"apiResponse": out}


COMPLETE = [{"protectionGroups": [group(1, 1), group(1, 2, "Failed")]}, DEAD, {"protectionGroups": [group(3, 1, sla=True)]}]
PARTIAL = [{"protectionGroups": [group(1, 1)]}, DEAD, {"error": True, "statusCode": 500, "item": 3, "errorType": "vendorError"}]
POLICIES = [policy(1), policy(3)]
RUN_KEYS = ["isBackupEnabled", "failedBackupJobsCount", "backupSuccessRatePercentage",
            "backupSlaComplianceRatePercentage", "staleProtectionJobsCount"]
POLICY_KEYS = ["isBackupImmutable", "isBackupTypesScheduled", "isDataLockComplianceModeEnabled"]


def run(key, payload):
    out = load(key.lower()).transform(payload)
    return out["transformedResponse"], out["additionalInfo"]["dataCollection"]


class ClusterGroups(unittest.TestCase):
    def test_a_complete_read_counts_every_cluster_and_ignores_the_disconnected_one(self):
        inner, dc = run("isBackupEnabled", body(COMPLETE))
        self.assertIs(inner["isBackupEnabled"], True)
        self.assertEqual(dc["status"], "success")
        inner, _ = run("failedBackupJobsCount", body(COMPLETE))
        self.assertEqual(inner["failedBackupJobsCount"], 1)
        inner, _ = run("backupSuccessRatePercentage", body(COMPLETE))
        self.assertEqual(inner["backupSuccessRatePercentage"], 66.67)
        inner, _ = run("backupSlaComplianceRatePercentage", body(COMPLETE))
        self.assertEqual(inner["backupSlaComplianceRatePercentage"], 66.67)
        inner, _ = run("staleProtectionJobsCount", body(COMPLETE))
        self.assertEqual(inner["staleProtectionJobsCount"], 1)  # the Failed one

    def test_a_connected_cluster_that_failed_makes_every_count_not_evaluated(self):
        for key in ["failedBackupJobsCount", "backupSuccessRatePercentage", "backupSlaComplianceRatePercentage",
                    "staleProtectionJobsCount"]:
            inner, dc = run(key, body(PARTIAL))
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc["status"], "error", key)
            self.assertIn("gamma (HTTP 500)", dc["errors"][0], key)
            self.assertNotIn("beta", dc["errors"][0], key)

    def test_a_successful_run_on_a_read_cluster_proves_backups_enabled_even_when_partial(self):
        inner, dc = run("isBackupEnabled", body(PARTIAL))
        self.assertIs(inner["isBackupEnabled"], True)
        self.assertIn("gamma (HTTP 500)", inner["reason"])
        nothing_good = [{"protectionGroups": [group(1, 1, "Failed")]}, DEAD,
                        {"error": True, "statusCode": 500, "item": 3, "errorType": "vendorError"}]
        inner, dc = run("isBackupEnabled", body(nothing_good))
        self.assertIsNone(inner["isBackupEnabled"])
        self.assertEqual(dc["status"], "error")

    def test_policy_checks_judge_in_use_policies_across_clusters(self):
        for key in POLICY_KEYS:
            inner, dc = run(key, body(COMPLETE, POLICIES))
            self.assertIs(inner[key], True, key)
        bad = [policy(1), policy(3, lock=None, schedule=False)]
        for key in POLICY_KEYS:
            inner, _ = run(key, body(COMPLETE, bad))
            self.assertIs(inner[key], False, key)
            self.assertIn("Gold-3", inner["reason"], key)

    def test_policy_checks_on_a_partial_read_keep_a_proven_false_and_never_prove_true(self):
        for key in POLICY_KEYS:
            inner, dc = run(key, body(PARTIAL, POLICIES))
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc["status"], "error", key)
        bad = [policy(1, lock=None, schedule=False), policy(3)]
        for key in POLICY_KEYS:
            inner, _ = run(key, body(PARTIAL, bad))
            self.assertIs(inner[key], False, key)

    def test_the_fan_out_cap_and_a_short_page_make_the_read_partial(self):
        capped = body(COMPLETE, iterateTruncated=True)
        inner, dc = run("failedBackupJobsCount", capped)
        self.assertIsNone(inner["failedBackupJobsCount"])
        self.assertIn("fan-out cap", dc["errors"][0])
        paged = [dict(COMPLETE[0], paginationCookie="x"), DEAD, COMPLETE[2]]
        inner, dc = run("staleProtectionJobsCount", body(paged))
        self.assertIsNone(inner["staleProtectionJobsCount"])
        self.assertIn("alpha (first page only)", dc["errors"][0])

    def test_the_tenant_wide_shape_still_reads_as_before(self):
        legacy = {"apiResponse": {"protectionGroups": [group(1, 1), group(1, 2, "Failed")], "policies": POLICIES}}
        inner, _ = run("failedBackupJobsCount", legacy)
        self.assertEqual(inner["failedBackupJobsCount"], 1)
        inner, _ = run("isBackupImmutable", legacy)
        self.assertIs(inner["isBackupImmutable"], True)
        no_runs = {"apiResponse": {"protectionGroups": [group(1, 1, run=False), group(1, 2, run=False)]}}
        for key in RUN_KEYS:
            inner, dc = run(key, no_runs)
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc.get("errorCode"), "VENDOR_DATA_NOT_EXPOSED", key)

    def test_every_run_check_returns_the_envelope(self):
        for key in RUN_KEYS + POLICY_KEYS:
            out = load(key.lower()).transform({"apiResponse": {"clusterGroups": "junk"}})
            self.assertIn("transformedResponse", out, key)
            self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error", key)
            self.assertIsNone(out["transformedResponse"][key], key)


if __name__ == "__main__":
    unittest.main()
