"""BeyondTrust Password Safe checks that could never pass: their thresholds were never defined.

isPasswordAutoManagementEnabled and requiredCoveragePercentage compared against
COVERAGE_THRESHOLD, and isPasswordRotationOnReleaseEnabled against ROTATION_THRESHOLD, none of
which existed in the file. The NameError was swallowed into a failed verdict. The values now
defined (80% and 50%) are the ones each docstring states and the sibling BeyondTrust transforms
use.

Every body below is synthetic and runs the file as production does, under the RestrictedPython
mirror in tools/restricted_sandbox.py, past the line that used to raise.
"""
import importlib.util
import json
import pathlib
import unittest

HERE = pathlib.Path(__file__).parent
ROOT = HERE.resolve().parents[2]


def _tool(name):
    spec = importlib.util.spec_from_file_location("bt_" + name, ROOT / "tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SANDBOX = _tool("restricted_sandbox")
NAMES = _tool("check_sandbox_names")


def verdict(test, filename, key, body):
    out = SANDBOX.load((HERE / filename).read_text(), "<transformation>")["transform"](body)
    text = json.dumps(out, default=str)
    test.assertNotIn("is not defined", text, text)
    test.assertEqual(out["additionalInfo"]["transformation"]["status"], "success", text)
    return out["transformedResponse"][key]


def accounts(flag, on, total):
    return [{"ManagedAccountID": i + 1, "AccountName": f"svc-{i + 1:03d}", flag: i < on}
            for i in range(total)]


class Thresholds(unittest.TestCase):
    def test_no_undefined_names(self):
        provided = NAMES.provided_names()
        for f in ("ispasswordautomanagementenabled.py", "ispasswordrotationonreleaseenabled.py",
                  "requiredcoveragepercentage.py"):
            self.assertEqual(NAMES.undefined_names((HERE / f).read_text(), provided), {}, f)

    def test_auto_management_at_80_percent_passes(self):
        body = accounts("AutoManagementFlag", 4, 5)
        self.assertIs(verdict(self, "ispasswordautomanagementenabled.py", "isPasswordAutoManagementEnabled", body), True)
        self.assertIs(verdict(self, "ispasswordautomanagementenabled.py", "isPasswordAutoManagementEnabled",
                              {"ManagedAccounts": body}), True)

    def test_auto_management_below_80_percent_fails(self):
        body = accounts("AutoManagementFlag", 3, 5)
        self.assertIs(verdict(self, "ispasswordautomanagementenabled.py", "isPasswordAutoManagementEnabled", body), False)

    def test_rotation_at_50_percent_passes(self):
        body = accounts("ChangePasswordAfterAnyReleaseFlag", 1, 2)
        self.assertIs(verdict(self, "ispasswordrotationonreleaseenabled.py", "isPasswordRotationOnReleaseEnabled", body), True)

    def test_rotation_below_50_percent_fails(self):
        body = accounts("ChangePasswordAfterAnyReleaseFlag", 1, 3)
        self.assertIs(verdict(self, "ispasswordrotationonreleaseenabled.py", "isPasswordRotationOnReleaseEnabled", body), False)

    def _coverage(self, covered):
        systems = [{"ManagedSystemID": i, "SystemName": f"host-{i:02d}"} for i in range(1, 6)]
        managed = [{"ManagedAccountID": 100 + i, "ManagedSystemID": i} for i in range(1, covered + 1)]
        return verdict(self, "requiredcoveragepercentage.py", "requiredCoveragePercentage",
                       {"managedSystems": systems, "managedAccounts": managed})

    def test_coverage_at_80_percent_passes(self):
        self.assertIs(self._coverage(4), True)

    def test_coverage_below_80_percent_fails(self):
        self.assertIs(self._coverage(2), False)


if __name__ == "__main__":
    unittest.main()
