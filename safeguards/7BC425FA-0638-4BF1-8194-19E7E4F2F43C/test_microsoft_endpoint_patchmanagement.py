"""Windows Defender One-Click patch management reads Defender Vulnerability Management, not the alerts list.

Before 2026-09-29 isPatchManagementEnabled/Valid came from getAlerts: any alert passed both.
"""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("mdepatch", Path(__file__).with_name("microsoft_endpoint_patchmanagement.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def body(assessed, crit, crit_high):
    return {"Schema": [{"Name": "AssessedDevices", "Type": "Int64"}],
            "Results": [{"AssessedDevices": assessed, "DevicesWithOverdueCritical": crit,
                         "DevicesWithOverdueCriticalOrHigh": crit_high}]}


class PatchManagement(unittest.TestCase):
    def res(self, payload):
        return m.transform(payload)["transformedResponse"]

    def test_fully_patched_passes_both(self):
        r = self.res(body(40, 0, 0))
        self.assertIs(r["isPatchManagementEnabled"], True)
        self.assertIs(r["isPatchManagementValid"], True)
        self.assertEqual(r["patchedCriticalHighPercentage"], 100)

    def test_overdue_high_only_fails_valid(self):
        r = self.res(body(40, 0, 3))
        self.assertIs(r["isPatchManagementEnabled"], True)
        self.assertIs(r["isPatchManagementValid"], False)
        self.assertEqual(r["patchedCriticalHighPercentage"], 92)

    def test_overdue_critical_fails_both(self):
        r = self.res(body(40, 2, 5))
        self.assertIs(r["isPatchManagementEnabled"], False)
        self.assertIs(r["isPatchManagementValid"], False)

    def test_no_inventory_is_not_measured(self):
        out = m.transform(body(0, 0, 0))
        self.assertIs(out["transformedResponse"]["isPatchManagementEnabled"], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_alerts_body_and_errors_fail(self):
        self.assertIs(self.res({"value": [{"id": "da1", "severity": "High", "title": "Suspicious PowerShell"}]})["isPatchManagementEnabled"], False)
        self.assertIs(self.res({"error": {"code": "Forbidden"}})["isPatchManagementValid"], False)
        self.assertIs(self.res({"Results": []})["isPatchManagementValid"], False)
        self.assertIs(self.res({})["isPatchManagementEnabled"], False)


if __name__ == "__main__":
    unittest.main()
