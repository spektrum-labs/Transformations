"""Qualys patchCompliancePercentage / criticalVulnerabilityCount: nothing scanned is not a pass (ENG-1353).

A reply with no HOST_LIST used to read 100% patch compliance and 0 critical vulnerabilities. It is now
Not evaluated (value None, dataCollection "error"). Hosts present with no open detections is still a
measured 100 / 0. Synthetic fixtures only.
"""
import importlib.util
import unittest
from pathlib import Path


def load(name):
    spec = importlib.util.spec_from_file_location("qualys_eng1353_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reply(hosts):
    response = {"DATETIME": "2026-01-01T00:00:00Z"}
    if hosts is not None:
        response["HOST_LIST"] = {"HOST": hosts}
    return {"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": response}}


def host(i, detections):
    return {"ID": str(100000 + i), "IP": "192.0.2." + str(i), "DETECTION_LIST": {"DETECTION": detections}}


def detection(severity, status):
    return {"QID": "38000", "SEVERITY": str(severity), "STATUS": status}


CASES = [("patchcompliancepercentage", "patchCompliancePercentage"),
         ("criticalvulnerabilitycount", "criticalVulnerabilityCount")]


class NothingScanned(unittest.TestCase):
    mods = {name: load(name) for name, _ in CASES}

    def run_case(self, name, key, payload):
        out = self.mods[name].transform(payload)
        return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]

    def test_no_host_list_is_not_evaluated(self):
        for name, key in CASES:
            with self.subTest(transform=name):
                self.assertEqual(self.run_case(name, key, reply(None)), (None, "error"))

    def test_empty_host_list_is_not_evaluated(self):
        for name, key in CASES:
            with self.subTest(transform=name):
                self.assertEqual(self.run_case(name, key, reply([])), (None, "error"))

    def test_empty_body_is_not_evaluated(self):
        for name, key in CASES:
            with self.subTest(transform=name):
                self.assertEqual(self.run_case(name, key, {}), (None, "error"))

    def test_unreadable_detection_is_not_evaluated(self):
        bad = reply([host(1, [{"QID": "38000", "SEVERITY": "not-a-number", "STATUS": "Active"}])])
        self.assertEqual(self.run_case("criticalvulnerabilitycount", "criticalVulnerabilityCount", bad),
                         (None, "error"))

    def test_hosts_with_no_detections_are_a_measured_clean_result(self):
        payload = reply([host(1, []), host(2, [])])
        self.assertEqual(self.run_case("patchcompliancepercentage", "patchCompliancePercentage", payload),
                         ("100", "success"))
        self.assertEqual(self.run_case("criticalvulnerabilitycount", "criticalVulnerabilityCount", payload),
                         (0, "success"))

    def test_open_critical_detections_are_counted(self):
        payload = reply([host(1, [detection(5, "Active"), detection(4, "New"), detection(3, "Active"),
                                  detection(5, "Fixed")])])
        self.assertEqual(self.run_case("criticalvulnerabilitycount", "criticalVulnerabilityCount", payload),
                         (2, "success"))
        # A share of fixed detections is graded only when Qualys echoes a filter naming open and fixed.
        payload["HOST_LIST_VM_DETECTION_OUTPUT"]["REQUEST"] = {"PARAM_LIST": {"PARAM": [
            {"KEY": "status", "VALUE": "New,Active,Re-Opened,Fixed"}]}}
        self.assertEqual(self.run_case("patchcompliancepercentage", "patchCompliancePercentage", payload),
                         ("25", "success"))


if __name__ == "__main__":
    unittest.main()
