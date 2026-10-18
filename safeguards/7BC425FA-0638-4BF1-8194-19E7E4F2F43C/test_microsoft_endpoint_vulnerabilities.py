"""Windows Defender One-Click vulnerability counts: Falcon Spotlight's keys and windows, read from the MDE export.

Fixtures follow the GET /api/machines/SoftwareVulnerabilitiesByMachine JSON shape (camelCase fields,
'YYYY-MM-DD HH:MM:SS.fffffff' timestamps) after IS merges the @odata.nextLink pages into `value`.
"""
import importlib.util
import json
import unittest
from datetime import datetime, timedelta
from pathlib import Path

spec = importlib.util.spec_from_file_location("mdevulns", Path(__file__).with_name("microsoft_endpoint_vulnerabilities.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

KEYS = ["openCriticalVulnerabilitiesCount", "openHighSeverityVulnerabilitiesCount", "overdueCriticalHighVulnerabilitiesCount"]


def seen(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).isoformat(sep=" ", timespec="microseconds") + "0"


def rec(device, cve, severity, days_ago, software="microsoft_edge", version="118.0.2088.46"):
    return {
        "id": device + "_" + software + "_" + version + "_" + cve,
        "cveId": cve,
        "deviceId": device,
        "deviceName": device[:6] + ".corp.example.com",
        "osPlatform": "Windows11",
        "softwareVendor": "microsoft",
        "softwareName": software,
        "softwareVersion": version,
        "vulnerabilitySeverityLevel": severity,
        "recommendedSecurityUpdate": "October 2026 Security Updates",
        "exploitabilityLevel": "NoExploit",
        "securityUpdateAvailable": True,
        "firstSeenTimestamp": seen(days_ago),
        "lastSeenTimestamp": seen(0),
        "rbacGroupName": "Servers",
    }


def body(records, next_link=None):
    out = {"@odata.context": "https://api.securitycenter.microsoft.com/api/$metadata#Collection(microsoft.windowsDefenderATP.api.ExportSoftwareVulnerabilityResponse)",
           "value": records}
    if next_link:
        out["@odata.nextLink"] = next_link
    return out


DEV_A = "1e5bc9d7e413ddd7902c2932e418702b84d0cc07"
DEV_B = "9a8f3c2b1d0e4f5a6b7c8d9e0f1a2b3c4d5e6f70"


class Vulnerabilities(unittest.TestCase):
    def run_t(self, payload):
        return m.transform(payload)

    def test_pass_recent_findings_only(self):
        out = self.run_t(body([rec(DEV_A, "CVE-2026-1001", "Critical", 3), rec(DEV_B, "CVE-2026-1002", "High", 20),
                               rec(DEV_A, "CVE-2026-0003", "Medium", 400)]))
        r = out["transformedResponse"]
        self.assertEqual(r["openCriticalVulnerabilitiesCount"], 1)
        self.assertEqual(r["openHighSeverityVulnerabilitiesCount"], 1)
        self.assertEqual(r["overdueCriticalHighVulnerabilitiesCount"], 0)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertEqual(out["additionalInfo"]["metadata"]["schemaVersion"], "2.0")
        self.assertTrue(out["additionalInfo"]["evaluation"]["passReasons"])

    def test_fail_overdue_windows_match_falcon(self):
        out = self.run_t(body([rec(DEV_A, "CVE-2026-2001", "Critical", 16), rec(DEV_A, "CVE-2026-2002", "Critical", 15),
                               rec(DEV_B, "CVE-2026-2003", "High", 31), rec(DEV_B, "CVE-2026-2004", "High", 30)]))
        r = out["transformedResponse"]
        self.assertEqual(r["openCriticalVulnerabilitiesCount"], 2)
        self.assertEqual(r["openHighSeverityVulnerabilitiesCount"], 2)
        self.assertEqual(r["overdueCriticalHighVulnerabilitiesCount"], 2)
        self.assertTrue(out["additionalInfo"]["evaluation"]["failReasons"])

    def test_same_cve_on_one_device_counts_once_with_earliest_first_seen(self):
        r = self.run_t(body([rec(DEV_A, "CVE-2026-3001", "Critical", 2, version="1.0"),
                             rec(DEV_A, "CVE-2026-3001", "Critical", 40, version="1.1"),
                             rec(DEV_B, "CVE-2026-3001", "Critical", 2)]))["transformedResponse"]
        self.assertEqual(r["openCriticalVulnerabilitiesCount"], 2)
        self.assertEqual(r["overdueCriticalHighVulnerabilitiesCount"], 1)
        self.assertEqual(r["distinctOpenCriticalOrHighCves"], 1)

    def test_only_medium_low_reads_measured_zero(self):
        r = self.run_t(body([rec(DEV_A, "CVE-2025-9001", "Low", 300), rec(DEV_B, "CVE-2025-9002", "Medium", 90)]))["transformedResponse"]
        for k in KEYS:
            self.assertEqual(r[k], 0)

    def test_string_and_wrapped_input(self):
        payload = json.dumps({"apiResponse": body([rec(DEV_A, "CVE-2026-1001", "High", 45)])})
        r = self.run_t(payload)["transformedResponse"]
        self.assertEqual(r["overdueCriticalHighVulnerabilitiesCount"], 1)

    def assert_unevaluated(self, payload):
        out = self.run_t(payload)
        for k in KEYS:
            self.assertIsNone(out["transformedResponse"][k])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        return out

    def test_empty_export_is_unevaluated(self):
        self.assert_unevaluated(body([]))

    def test_error_bodies_are_unevaluated(self):
        self.assert_unevaluated({"error": {"code": "Forbidden", "message": "Missing application roles. Required: Vulnerability.Read.All"}})
        self.assert_unevaluated({"status": "Error", "status_code": 403})
        self.assert_unevaluated({})
        self.assert_unevaluated(None)
        self.assert_unevaluated("not json")

    def test_truncated_read_is_unevaluated(self):
        out = self.assert_unevaluated(body([rec(DEV_A, "CVE-2026-1001", "Critical", 1)],
                                           next_link="https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine?pageIndex=51&pageSize=50000"))
        self.assertIn("partial", out["additionalInfo"]["dataCollection"]["errors"][0])
        trunc = body([rec(DEV_A, "CVE-2026-1001", "Critical", 1)])
        trunc["truncated"] = True
        self.assert_unevaluated(trunc)

    def test_record_without_first_seen_is_unevaluated(self):
        bad = rec(DEV_A, "CVE-2026-1001", "Critical", 1)
        bad["firstSeenTimestamp"] = None
        self.assert_unevaluated(body([bad]))
        nosev = rec(DEV_A, "CVE-2026-1001", "Critical", 1)
        del nosev["vulnerabilitySeverityLevel"]
        self.assert_unevaluated(body([nosev]))

    def test_exception_path_is_unevaluated_not_failed(self):
        # A body whose every read raises drives transform() into its except path. Token-Service grades a
        # None as Failed unless dataCollection.status is "error", so that path must carry api_errors.
        class Poisoned(dict):
            def __init__(self):
                super().__init__(poisoned=True)

            def boom(self, *args, **kwargs):
                raise RuntimeError("poisoned read")

            get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

            def __len__(self):
                return 1

        out = self.assert_unevaluated(Poisoned())
        self.assertIn("Transformation error", out["additionalInfo"]["dataCollection"]["errors"][0])
        self.assertEqual(out["additionalInfo"]["transformation"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
