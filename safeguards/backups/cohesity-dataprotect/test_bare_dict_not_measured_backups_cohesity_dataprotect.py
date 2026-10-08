"""The boolean Cohesity DataProtect checks return the full envelope, with "not measured" read from the value.

These transforms used to return a bare {key: False, "reason": ...} with no additionalInfo, so Token-Service graded
every unreadable body as a FAIL. Each body in UNMEASURED proves nothing about the estate: the criterion must be None
AND dataCollection.status "error". A well-formed body that says off stays False with status "success", and a passing
body stays True. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("bdnm_" + name, os.path.join(HERE, name + ".py"))
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


def group(i, status="Succeeded", policy="p1"):
    return {"id": "g%d" % i, "name": "pg%d" % i, "policyId": policy, "isActive": True, "isPaused": False,
            "isDeleted": False, "lastRun": {"localBackupInfo": {"status": status}}}


def policy(mode="Compliance", inc_unit="Hours"):
    reg = {"retention": {"unit": "Days", "duration": 30}}
    if mode:
        reg["retention"]["dataLockConfig"] = {"mode": mode, "unit": "Days", "duration": 30}
    if inc_unit:
        reg["incremental"] = {"schedule": {"unit": inc_unit}}
    return {"id": "p1", "name": "policy-p1", "backupPolicy": {"regular": reg}}


GROUPS = {"protectionGroups": [group(0)]}
POSTURE = {"protectionGroups": [group(0)], "policies": [policy()]}

UNMEASURED = [
    ("empty_dict", lambda: {}),
    ("empty_list", lambda: []),
    ("not_available", lambda: {"status": "Not Available"}),
    ("refusal_401", lambda: {"error": "Unauthorized", "statusCode": 401}),
    ("poisoned", lambda: Poisoned()),
]

FILES = {
    "isbackupenabled": "isBackupEnabled",
    "isbackupimmutable": "isBackupImmutable",
    "isbackuptypesscheduled": "isBackupTypesScheduled",
    "isdatalockcompliancemodeenabled": "isDataLockComplianceModeEnabled",
    "ismfaenforcedforusers": "isMFAEnforcedForUsers",
    "isssoenabled": "isSSOEnabled",
}

# (file, body that is present but cannot answer the check) -> None + "error"
MISSING = [
    ("isbackupenabled", {"protectionGroups": {"not": "a list"}}),
    ("isbackupimmutable", {"protectionGroups": [group(0, policy="gone")], "policies": [policy()]}),
    ("isbackuptypesscheduled", dict(POSTURE, paginationCookie="next")),
    ("isdatalockcompliancemodeenabled", {"protectionGroups": [group(0)], "policies": "nope"}),
    ("ismfaenforcedforusers", {"deploymentType": "HeliosSaas"}),
    ("ismfaenforcedforusers", {"deploymentType": "HeliosOnPrem", "heliosOnPremConfig": {}}),
    ("ismfaenforcedforusers", {"deploymentType": "SomethingElse"}),
    ("isssoenabled", {"idps": "nope"}),
]

# (file, well-formed body that says off) -> False + "success"
MEASURED_OFF = [
    ("isbackupenabled", {"protectionGroups": [group(0, status="Failed")]}),
    ("isbackupimmutable", {"protectionGroups": [group(0)], "policies": [policy(mode=None)]}),
    ("isbackuptypesscheduled", {"protectionGroups": [group(0)], "policies": [policy(inc_unit=None)]}),
    ("isdatalockcompliancemodeenabled", {"protectionGroups": [group(0)], "policies": [policy(mode="Administrative")]}),
    ("ismfaenforcedforusers", {"deploymentType": "HeliosSaas", "heliosSaasConfig": {"mfaStatus": "OptOut"}}),
    ("ismfaenforcedforusers", {"deploymentType": "HeliosOnPrem", "heliosOnPremConfig": {"mfa": False}}),
    ("isssoenabled", {"idps": [{"name": "idp", "isEnabled": False}]}),
]

# (file, passing body) -> True + "success"
MEASURED_ON = [
    ("isbackupenabled", GROUPS),
    ("isbackupimmutable", POSTURE),
    ("isbackuptypesscheduled", POSTURE),
    ("isdatalockcompliancemodeenabled", POSTURE),
    ("ismfaenforcedforusers", {"deploymentType": "HeliosSaas", "heliosSaasConfig": {"mfaStatus": "OptIn"}}),
    ("isssoenabled", {"idps": [{"name": "idp", "domain": "example", "isEnabled": True}]}),
]


class BareDictBecomesEnvelope(unittest.TestCase):
    def check(self, name, body, value, status):
        key = FILES[name]
        out = load(name).transform(body)
        self.assertIn("transformedResponse", out)
        inner = out["transformedResponse"]
        self.assertIs(inner[key], value)
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], status)
        if status == "error":
            self.assertTrue(collection["errors"])
            self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))
        else:
            self.assertEqual(collection["errors"], [])
        self.assertTrue(inner.get("reason"))

    def test_unreadable_bodies_are_not_measured(self):
        for name in FILES:
            for case, body in UNMEASURED:
                with self.subTest(transform=name, body=case):
                    self.check(name, body(), None, "error")

    def test_present_but_unanswerable_is_not_measured(self):
        for name, body in MISSING:
            with self.subTest(transform=name, body=body):
                self.check(name, body, None, "error")

    def test_measured_off_stays_false(self):
        for name, body in MEASURED_OFF:
            with self.subTest(transform=name, body=body):
                self.check(name, body, False, "success")

    def test_measured_on_stays_true(self):
        for name, body in MEASURED_ON:
            with self.subTest(transform=name, body=body):
                self.check(name, body, True, "success")


if __name__ == "__main__":
    unittest.main()
