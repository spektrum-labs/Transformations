"""Qualys confirmedLicensePurchased, isASMEnabled and isASMLoggingEnabled read the real body shapes.

confirmedLicensePurchased: GET /qps/rest/portal/version answers
{"licenseStatus": {"ServiceResponse": {"responseCode": "SUCCESS", ...}}}. The transform never
unwrapped ServiceResponse and fell back to a generic signal that read False, so a working
subscription failed. isASMEnabled / isASMLoggingEnabled: the schedule list arrives as
SCHEDULE_SCAN_LIST_OUTPUT; the transform looked for SCHEDULED_SCAN_LIST_OUTPUT and read False.

All fixtures are synthetic.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location("qualys_" + name, HERE / (name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lic = load("confirmedlicensepurchased")
asm = load("asm_transform")
KEY = "confirmedLicensePurchased"

PORTAL_SUCCESS = {"licenseStatus": {"ServiceResponse": {
    "responseCode": "SUCCESS", "count": "1",
    "data": {"Portal-Version": {"PortalApplication-VERSION": "3.25.0.0-10", "UD-VERSION": "2.16.1-3-20"}}}}}


def portal(code):
    body = copy.deepcopy(PORTAL_SUCCESS)
    body["licenseStatus"]["ServiceResponse"]["responseCode"] = code
    return body


def scan(scan_id, active):
    return {"ID": str(scan_id), "ACTIVE": "1" if active else "0", "TITLE": "Synthetic scan",
            "TARGET": "192.0.2.10", "ISCANNER_NAME": "External Scanner",
            "SCHEDULE": {"DAILY": {"@frequency_days": "1"}, "START_HOUR": "0"}}


def schedule_body(scans, root="SCHEDULE_SCAN_LIST_OUTPUT", list_key="SCHEDULE_SCAN_LIST"):
    response = {"DATETIME": "2026-01-01T00:00:00Z"}
    if scans is not None:
        response[list_key] = {"SCAN": scans}
    return {root: {"RESPONSE": response}}


class LicenceVerdicts(unittest.TestCase):
    def res(self, body):
        return lic.transform(body)["transformedResponse"][KEY]

    def test_success_body_passes(self):
        out = lic.transform(PORTAL_SUCCESS)
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertIn("portal 3.25.0.0-10", out["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_success_body_unwrapped_and_as_string(self):
        self.assertIs(self.res(PORTAL_SUCCESS["licenseStatus"]), True)
        self.assertIs(self.res(json.dumps(PORTAL_SUCCESS)), True)
        self.assertIs(self.res({"response": PORTAL_SUCCESS}), True)

    def test_auth_and_permission_codes_not_evaluated(self):
        for code in ("INVALID_CREDENTIALS", "UNAUTHORIZED", "INSUFFICIENT_PRIVILEGES", "INVALID_REQUEST", "OTHER_ERROR", ""):
            self.assertIsNone(self.res(portal(code)), code)

    def test_subscription_expired_fails(self):
        self.assertIs(self.res(portal("SUBSCRIPTION_EXPIRED")), False)

    def test_empty_and_error_bodies_not_evaluated(self):
        for body in ({}, None, "{}", {"error": "boom"}, {"errors": ["boom"]},
                     {"error": True, "message": "Integration execution error: HTTP 401"},
                     {"message": "Integration execution error: HTTP 401"},
                     {"licenseStatus": {}}, {"licenseStatus": {"error": "boom"}}):
            self.assertIsNone(self.res(body), repr(body))

    def test_legacy_flag_still_decides(self):
        self.assertIs(self.res({"licensePurchased": True}), True)
        self.assertIs(self.res({"licensePurchased": False}), False)


class AsmVerdicts(unittest.TestCase):
    def res(self, body):
        return asm.transform(body)["transformedResponse"]

    def test_active_schedule_passes_both(self):
        r = self.res(schedule_body([scan(1, False), scan(2, True), scan(3, False)]))
        self.assertIs(r["isASMEnabled"], True)
        self.assertIs(r["isASMLoggingEnabled"], True)
        reasons = asm.transform(schedule_body([scan(1, False), scan(2, True)]))["additionalInfo"]["evaluation"]["passReasons"]
        self.assertTrue(any(x.startswith("Logging inferred:") and "(1 active schedules)" in x for x in reasons), reasons)

    def test_single_active_scan_as_dict(self):
        self.assertIs(self.res(schedule_body(scan(1, True)))["isASMEnabled"], True)

    def test_all_deactivated_fails(self):
        r = self.res(schedule_body([scan(1, False), scan(2, False)]))
        self.assertIs(r["isASMEnabled"], False)
        self.assertIs(r["isASMLoggingEnabled"], False)

    def test_no_schedules_fails(self):
        r = self.res(schedule_body(None))
        self.assertIs(r["isASMEnabled"], False)
        self.assertIs(r["isASMLoggingEnabled"], False)

    def test_schedule_root_without_response_not_evaluated(self):
        r = self.res({"SCHEDULE_SCAN_LIST_OUTPUT": {}})
        self.assertIsNone(r["isASMEnabled"])
        self.assertIsNone(r["isASMLoggingEnabled"])

    def test_error_and_empty_bodies_not_evaluated(self):
        for body in ({}, None, "{}", [], {"error": "boom"}, {"errors": ["boom"]},
                     {"error": True, "message": "Integration execution error: HTTP 401"},
                     {"SIMPLE_RETURN": {"RESPONSE": {"CODE": "2000", "TEXT": "Bad Login/Password"}}},
                     {"unrelated": "shape"}):
            r = self.res(body)
            self.assertIsNone(r["isASMEnabled"], repr(body))
            self.assertIsNone(r["isASMLoggingEnabled"], repr(body))

    def test_legacy_spelling_keeps_old_rule(self):
        body = schedule_body([scan(1, False)], root="SCHEDULED_SCAN_LIST_OUTPUT", list_key="SCHEDULED_SCAN_LIST")
        self.assertIs(self.res(body)["isASMEnabled"], True)

    def test_explicit_flags_decide(self):
        r = self.res({"isASMEnabled": False, "isASMLoggingEnabled": True})
        self.assertIs(r["isASMEnabled"], False)
        self.assertIs(r["isASMLoggingEnabled"], True)

    def test_detection_list_unchanged(self):
        body = {"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": {"HOST_LIST": {"HOST": [
            {"ID": "1", "DETECTION_LIST": {"DETECTION": [{"QID": "1"}]}}]}}}}
        r = self.res(body)
        self.assertIs(r["isASMEnabled"], True)
        self.assertIs(r["isASMLoggingEnabled"], True)
        empty = self.res({"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": {}}})
        self.assertIs(empty["isASMEnabled"], False)


if __name__ == "__main__":
    unittest.main()
