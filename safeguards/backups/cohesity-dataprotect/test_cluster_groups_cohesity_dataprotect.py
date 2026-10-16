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


CLUSTERS = {"cohesityClusters": [{"clusterId": 1111, "clusterName": "alpha", "isConnectedToHelios": True},
                                 {"clusterId": 2222, "clusterName": "beta", "isConnectedToHelios": False},
                                 {"clusterId": 3333, "clusterName": "gamma", "isConnectedToHelios": True}]}
# Integration-Service's continueOnItemError record carries the iterate parameter's value under "item": the clusterId.
DEAD = {"error": True, "statusCode": 502, "item": 2222, "errorType": "vendorError"}
ALIVE = {"cohesityClusters": [c for c in CLUSTERS["cohesityClusters"] if c["isConnectedToHelios"]]}


def body(slots, policies=None, **extra):
    out = {"clusters": copy.deepcopy(CLUSTERS), "clusterGroups": copy.deepcopy(slots),
           "iterateStats": {"clusterGroups": {"itemsTotal": 3, "itemsProcessed": 3, "itemErrors": 1, "iterateTruncated": False}},
           "itemErrors": 1}
    if policies is not None:
        out["policies"] = copy.deepcopy(policies)
    out.update(extra)
    return {"apiResponse": out}


COMPLETE = [{"protectionGroups": [group(1111, 1), group(1111, 2, "Failed")]}, DEAD, {"protectionGroups": [group(3333, 1, sla=True)]}]
PARTIAL = [{"protectionGroups": [group(1111, 1)]}, DEAD, {"error": True, "statusCode": 500, "item": 3333, "errorType": "vendorError"}]
POLICIES = [policy(1111), policy(3333)]
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
                        {"error": True, "statusCode": 500, "item": 3333, "errorType": "vendorError"}]
        inner, dc = run("isBackupEnabled", body(nothing_good))
        self.assertIsNone(inner["isBackupEnabled"])
        self.assertEqual(dc["status"], "error")

    def test_policy_checks_judge_in_use_policies_across_clusters(self):
        # every registered cluster read: True
        all_read = [COMPLETE[0], COMPLETE[2]]
        for key in POLICY_KEYS:
            payload = body(all_read, POLICIES)
            payload["apiResponse"]["clusters"] = copy.deepcopy(ALIVE)
            inner, dc = run(key, payload)
            self.assertIs(inner[key], True, key)
        # a registered cluster not connected to Helios was never read: compliant so far, but not proven for the estate
        for key in POLICY_KEYS:
            inner, dc = run(key, body(COMPLETE, POLICIES))
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc["status"], "error", key)
            self.assertIn("not connected to Helios, so not read: beta", dc["errors"][0], key)
        bad = [policy(1111), policy(3333, lock=None, schedule=False)]
        for key in POLICY_KEYS:
            inner, _ = run(key, body(COMPLETE, bad))
            self.assertIs(inner[key], False, key)
            self.assertIn("Gold-3", inner["reason"], key)

    def test_policy_checks_on_a_partial_read_keep_a_proven_false_and_never_prove_true(self):
        for key in POLICY_KEYS:
            inner, dc = run(key, body(PARTIAL, POLICIES))
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc["status"], "error", key)
        bad = [policy(1111, lock=None, schedule=False), policy(3333)]
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
        legacy = {"apiResponse": {"protectionGroups": [group(1111, 1), group(1111, 2, "Failed")], "policies": POLICIES}}
        inner, _ = run("failedBackupJobsCount", legacy)
        self.assertEqual(inner["failedBackupJobsCount"], 1)
        inner, _ = run("isBackupImmutable", legacy)
        self.assertIs(inner["isBackupImmutable"], True)
        no_runs = {"apiResponse": {"protectionGroups": [group(1, 1, run=False), group(1111, 2, run=False)]}}
        for key in RUN_KEYS:
            inner, dc = run(key, no_runs)
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc.get("errorCode"), "VENDOR_DATA_NOT_EXPOSED", key)

    def test_no_readable_cluster_is_not_evaluated_never_failed(self):
        all_dead = {"cohesityClusters": [{"clusterId": 2222, "clusterName": "beta", "isConnectedToHelios": False}]}
        for key in RUN_KEYS + POLICY_KEYS:
            payload = body([DEAD], POLICIES)
            payload["apiResponse"]["clusters"] = copy.deepcopy(all_dead)
            inner, dc = run(key, payload)
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc["status"], "error", key)
            self.assertIn("not connected to Helios: beta", dc["errors"][0], key)
        for key in RUN_KEYS + POLICY_KEYS:
            payload = body([], POLICIES)
            payload["apiResponse"]["clusters"] = {"cohesityClusters": []}
            inner, dc = run(key, payload)
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc["status"], "error", key)

    def test_slots_are_matched_to_clusters_by_id_not_position(self):
        # The error record echoes cluster 2 but sits in slot 0; the data slots carry cluster 3 and 1 group ids.
        shuffled = [DEAD, {"protectionGroups": [group(3333, 1, sla=True)]}, {"protectionGroups": [group(1111, 1), group(1111, 2, "Failed")]}]
        inner, dc = run("failedBackupJobsCount", body(shuffled))
        self.assertEqual(inner["failedBackupJobsCount"], 1)
        self.assertEqual(dc["status"], "success")
        # A failed read of a connected cluster is partial even when a disconnected cluster sits at its position.
        swapped = [{"error": True, "statusCode": 500, "item": 3333, "errorType": "vendorError"}, DEAD,
                   {"protectionGroups": [group(1111, 1)]}]
        inner, dc = run("failedBackupJobsCount", body(swapped))
        self.assertIsNone(inner["failedBackupJobsCount"])
        self.assertIn("gamma (HTTP 500)", dc["errors"][0])

    def test_fewer_slots_than_clusters_is_partial(self):
        two_slots = [{"protectionGroups": [group(1111, 1)]}, DEAD]
        inner, dc = run("staleProtectionJobsCount", body(two_slots))
        self.assertIsNone(inner["staleProtectionJobsCount"])
        self.assertIn("2 of 3 clusters answered", dc["errors"][0])

    def test_a_run_without_a_status_is_unreadable_not_never_ran(self):
        odd = [{"protectionGroups": [group(1111, 1), dict(group(1111, 2), lastRun={"archivalInfo": {}})]}, DEAD,
               {"protectionGroups": [group(3333, 1)]}]
        inner, dc = run("failedBackupJobsCount", body(odd))
        self.assertIsNone(inner["failedBackupJobsCount"])
        self.assertIn("no local backup status", dc["errors"][0])
        fresh = [{"protectionGroups": [group(1111, 1), group(1111, 2, run=False)]}, DEAD, {"protectionGroups": [group(3333, 1)]}]
        inner, dc = run("failedBackupJobsCount", body(fresh))
        self.assertEqual(inner["failedBackupJobsCount"], 0)
        self.assertEqual(inner["groupsNotRunYet"], ["pg-1111-2"])

    def test_a_false_resting_on_some_clusters_names_the_ones_not_read(self):
        thin = [{"protectionGroups": []}, DEAD, {"protectionGroups": [group(3333, 1, "Failed")]}]
        inner, dc = run("isBackupEnabled", body(thin))
        self.assertIs(inner["isBackupEnabled"], False)
        self.assertIn("not connected to Helios, so not read: beta", inner["reason"])
        empty = [{"protectionGroups": []}, DEAD, {"protectionGroups": []}]
        for key in POLICY_KEYS:
            inner, dc = run(key, body(empty, POLICIES))
            self.assertIs(inner[key], False, key)
            self.assertIn("beta", inner["reason"], key)

    def test_a_cluster_that_returns_no_last_run_at_all_is_not_evaluated_for_the_run_checks(self):
        odd = [{"protectionGroups": [group(1111, 1), group(1111, 2, "Failed")]}, DEAD,
               {"protectionGroups": [group(3333, 1, run=False), group(3333, 2, run=False)]}]
        for key in RUN_KEYS:
            inner, dc = run(key, body(odd))
            if key == "isBackupEnabled":
                # alpha already proves a backup ran: a proven True stands, with the unjudged cluster noted
                self.assertIs(inner[key], True)
                self.assertIn("no last-run information from: gamma", inner["reason"])
                continue
            self.assertIsNone(inner[key], key)
            self.assertEqual(dc.get("errorCode"), "VENDOR_DATA_NOT_EXPOSED", key)
            self.assertIn("gamma", dc["errors"][0], key)
        # nothing proven on the readable cluster either: Not evaluated, never False
        nothing = [{"protectionGroups": [group(1111, 1, "Failed")]}, DEAD,
                   {"protectionGroups": [group(3333, 1, run=False)]}]
        inner, dc = run("isBackupEnabled", body(nothing))
        self.assertIsNone(inner["isBackupEnabled"])
        self.assertEqual(dc.get("errorCode"), "VENDOR_DATA_NOT_EXPOSED")
        # a cluster whose only run-less groups are paused or inactive is not judged, so it does not block
        quiet = [{"protectionGroups": [group(1111, 1), group(1111, 2, "Failed")]}, DEAD,
                 {"protectionGroups": [group(3333, 1, run=False, active=False), dict(group(3333, 2, run=False), isPaused=True)]}]
        inner, dc = run("failedBackupJobsCount", body(quiet))
        self.assertEqual(inner["failedBackupJobsCount"], 1)
        # the policy checks do not need runs: with beta disconnected they are None because of beta, never
        # because of gamma's missing runs; with every cluster connected they answer True
        for key in POLICY_KEYS:
            inner, dc = run(key, body(odd, POLICIES))
            self.assertIsNone(inner[key], key)
            self.assertNotEqual(dc.get("errorCode"), "VENDOR_DATA_NOT_EXPOSED", key)
            self.assertIn("beta", dc["errors"][0], key)
            self.assertNotIn("gamma", dc["errors"][0] + str(inner.get("reason")), key)
            payload = body([odd[0], odd[2]], POLICIES)
            payload["apiResponse"]["clusters"] = copy.deepcopy(ALIVE)
            inner, dc = run(key, payload)
            self.assertIs(inner[key], True, key)
            self.assertEqual(dc["status"], "success", key)

    def test_counts_name_the_clusters_not_read(self):
        inner, dc = run("failedBackupJobsCount", body(COMPLETE))
        self.assertEqual(inner["failedBackupJobsCount"], 1)
        self.assertIn("not connected to Helios, so not read: beta", inner["reason"])

    def test_every_run_check_returns_the_envelope(self):
        for key in RUN_KEYS + POLICY_KEYS:
            out = load(key.lower()).transform({"apiResponse": {"clusterGroups": "junk"}})
            self.assertIn("transformedResponse", out, key)
            self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error", key)
            self.assertIsNone(out["transformedResponse"][key], key)


if __name__ == "__main__":
    unittest.main()
