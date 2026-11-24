"""Safe Security checks that could never pass: each read a name nothing defined.

isAssetInventoryPopulated, isCriticalFindingsMonitored, isIntegrationsConnected and
isSAFEScoreAboveThreshold each compared against a threshold constant that was never defined
(and isCriticalFindingsMonitored used timezone/timedelta without importing them). The NameError
was swallowed by `except Exception` into a failed verdict, and the gates stayed green because
their no-evidence bodies return before reaching the comparison. Two files also never returned
their result from evaluate(), so even a defined constant would not have produced a pass.

Every body below is synthetic and runs the file as production does, under the RestrictedPython
mirror in tools/restricted_sandbox.py, past the line that used to raise.
"""
import importlib.util
import json
import pathlib
import unittest
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).parent
ROOT = HERE.resolve().parents[2]


def _tool(name):
    spec = importlib.util.spec_from_file_location("ss_" + name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SANDBOX = _tool("restricted_sandbox")
NAMES = _tool("check_sandbox_names")


def run(filename, body):
    transform = SANDBOX.load((HERE / filename).read_text(), "<transformation>")["transform"]
    return transform(body)


def ago(**kw):
    return (datetime.now(timezone.utc) - timedelta(**kw)).isoformat()


class Base(unittest.TestCase):
    FILE = ""
    KEY = ""

    def verdict(self, body):
        out = run(self.FILE, body)
        text = json.dumps(out, default=str)
        self.assertNotIn("is not defined", text, text)
        self.assertEqual(out["additionalInfo"]["transformation"]["status"], "success", text)
        return out["transformedResponse"][self.KEY]

    def test_no_undefined_names(self):
        if not self.FILE:
            self.skipTest("base")
        code = (HERE / self.FILE).read_text()
        self.assertEqual(NAMES.undefined_names(code, NAMES.provided_names()), {})


class AssetInventory(Base):
    FILE, KEY = "isassetinventorypopulated.py", "isAssetInventoryPopulated"

    def test_reported_count_passes(self):
        self.assertIs(self.verdict({"totalCount": 42, "values": []}), True)

    def test_listed_assets_pass_without_a_count(self):
        self.assertIs(self.verdict({"values": [{"id": "asset-0001"}, {"id": "asset-0002"}]}), True)

    def test_empty_inventory_fails(self):
        self.assertIs(self.verdict({"totalCount": 0, "values": []}), False)

    def test_a_bool_is_not_a_count(self):
        self.assertIs(self.verdict({"totalCount": True}), False)


class CriticalFindings(Base):
    FILE, KEY = "iscriticalfindingsmonitored.py", "isCriticalFindingsMonitored"

    def test_recent_critical_finding_passes(self):
        body = {"totalCount": 3, "values": [{"id": "f-1", "updatedAt": ago(days=2)},
                                            {"id": "f-2", "updatedAt": ago(days=60)}]}
        self.assertIs(self.verdict(body), True)

    def test_naive_timestamp_is_read_as_utc(self):
        naive = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None).isoformat()
        self.assertIs(self.verdict({"values": [{"id": "f-1", "createdAt": naive}]}), True)

    def test_stale_findings_fail(self):
        self.assertIs(self.verdict({"totalCount": 1, "values": [{"id": "f-1", "updatedAt": ago(days=90)}]}), False)

    def test_no_readable_timestamp_fails(self):
        self.assertIs(self.verdict({"totalCount": 1, "values": [{"id": "f-1", "updatedAt": "not a date"}]}), False)

    def test_no_findings_fail(self):
        self.assertIs(self.verdict({"totalCount": 0, "values": []}), False)


class Integrations(Base):
    FILE, KEY = "isintegrationsconnected.py", "isIntegrationsConnected"

    def test_active_integration_passes(self):
        body = {"values": [{"id": "int-1", "name": "Example EDR", "status": "ACTIVE"},
                           {"id": "int-2", "name": "Example SIEM", "status": "DISCONNECTED"}]}
        self.assertIs(self.verdict(body), True)

    def test_only_inactive_integrations_fail(self):
        self.assertIs(self.verdict({"values": [{"id": "int-1", "name": "Example EDR", "status": "ERROR"}]}), False)

    def test_bare_status_envelope_is_not_an_integration(self):
        self.assertIs(self.verdict({"status": "active"}), False)

    def test_empty_list_fails(self):
        self.assertIs(self.verdict({"values": []}), False)


class SafeScore(Base):
    FILE, KEY = "issafescoreabovethreshold.py", "isSAFEScoreAboveThreshold"

    def test_good_grade_passes(self):
        self.assertIs(self.verdict({"grade": "B"}), True)

    def test_poor_grade_fails(self):
        self.assertIs(self.verdict({"grade": "D"}), False)

    def test_low_breach_likelihood_passes(self):
        self.assertIs(self.verdict({"breachLikelihood": 4.5}), True)      # percent
        self.assertIs(self.verdict({"breachLikelihood": 0.045}), True)    # probability

    def test_high_breach_likelihood_fails(self):
        self.assertIs(self.verdict({"breachLikelihood": 35}), False)

    def test_score_of_unknown_direction_is_not_a_likelihood(self):
        # The SAFE Score runs 0-5 with higher better; a poor 1.5 must not read as "1.5% likely".
        self.assertIs(self.verdict({"overallScore": 1.5}), False)
        self.assertIs(self.verdict({"riskScore": 2}), False)

    def test_out_of_range_or_bool_likelihood_fails(self):
        self.assertIs(self.verdict({"breachLikelihood": -3}), False)
        self.assertIs(self.verdict({"breachLikelihood": True}), False)


del Base

if __name__ == "__main__":
    unittest.main()
