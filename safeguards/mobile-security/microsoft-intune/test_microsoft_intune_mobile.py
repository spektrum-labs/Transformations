"""Microsoft Intune (Mobile Security): isMdmManaged, deviceCompliancePercentage, isPasscodeCompliant.

Fixture bodies follow the Microsoft Graph v1.0 response shapes on learn.microsoft.com (linked in each transform).
"""
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location("intune_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MDM = load("isMdmManaged")
PCT = load("deviceCompliancePercentage")
PASS = load("isPasscodeCompliant")


def run(module, key, payload):
    out = module.transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def overview(ios, android):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/managedDeviceOverview/$entity",
            "id": "42a91653", "enrolledDeviceCount": 40, "mdmEnrolledCount": 38, "dualEnrolledDeviceCount": 0,
            "deviceOperatingSystemSummary": {"androidCount": android, "iosCount": ios, "macOSCount": 3,
                                             "windowsCount": 30, "unknownCount": 0}}


def summary(compliant, non_compliant, error=0, unknown=0, not_applicable=0):
    return {"id": "8c4de8a7", "inGracePeriodCount": 0, "configManagerCount": 0, "unknownDeviceCount": unknown,
            "notApplicableDeviceCount": not_applicable, "compliantDeviceCount": compliant, "remediatedDeviceCount": 0,
            "nonCompliantDeviceCount": non_compliant, "errorDeviceCount": error, "conflictDeviceCount": 0}


def policies(*items):
    return {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#deviceManagement/deviceCompliancePolicies",
            "value": list(items)}


IOS_ON = {"@odata.type": "#microsoft.graph.iosCompliancePolicy", "id": "p1", "displayName": "iOS", "passcodeRequired": True}
IOS_OFF = {"@odata.type": "#microsoft.graph.iosCompliancePolicy", "id": "p2", "displayName": "iOS lax", "passcodeRequired": False}
AND_ON = {"@odata.type": "#microsoft.graph.androidWorkProfileCompliancePolicy", "id": "p3", "displayName": "Android WP",
          "passwordRequired": True}
WIN = {"@odata.type": "#microsoft.graph.windows10CompliancePolicy", "id": "p4", "displayName": "Windows",
       "passwordRequired": False}


# --- real shapes ---------------------------------------------------------------------------------------------

def test_mdm_counts_mobile_devices():
    assert run(MDM, "isMdmManaged", overview(8, 12)) == (True, "success")
    assert MDM.transform(overview(8, 12))["transformedResponse"]["managedMobileDeviceCount"] == 20


def test_mdm_doc_sample_value_wrapper():
    assert run(MDM, "isMdmManaged", {"value": overview(1, 0)}) == (True, "success")


def test_mdm_zero_mobile_is_measured_false():
    assert run(MDM, "isMdmManaged", overview(0, 0)) == (False, "success")


def test_compliance_percentage_rounds_down():
    # 189 / 199 = 94.97 -> 94.9, never 95.0; notApplicable is excluded from the denominator
    assert run(PCT, "deviceCompliancePercentage", summary(189, 10, not_applicable=50)) == (94.9, "success")
    assert run(PCT, "deviceCompliancePercentage", summary(40, 0)) == (100.0, "success")


def test_compliance_unknown_counts_against():
    assert run(PCT, "deviceCompliancePercentage", summary(3, 0, unknown=1)) == (75.0, "success")


def test_passcode_all_mobile_policies_require_it():
    assert run(PASS, "isPasscodeCompliant", policies(IOS_ON, AND_ON, WIN)) == (True, "success")


def test_passcode_one_lax_policy_fails():
    assert run(PASS, "isPasscodeCompliant", policies(IOS_ON, IOS_OFF)) == (False, "success")


def test_passcode_no_mobile_policy_is_measured_false():
    assert run(PASS, "isPasscodeCompliant", policies(WIN)) == (False, "success")
    assert run(PASS, "isPasscodeCompliant", policies()) == (False, "success")


# --- empty and error shapes: never an answer ------------------------------------------------------------------

NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "graph_403": {"error": {"code": "Forbidden", "message": "Missing DeviceManagementManagedDevices.Read.All"}},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"value": [{"id": "u1", "userPrincipalName": "a@b.c"}]},
    "not_found_404": {"statusCode": 404, "error": "Not Found"},
    "pagination_incomplete": {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429},
}


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_mdm_no_evidence(name):
    assert run(MDM, "isMdmManaged", NO_EVIDENCE[name]) == (None, "error")


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
def test_compliance_no_evidence(name):
    assert run(PCT, "deviceCompliancePercentage", NO_EVIDENCE[name]) == (None, "error")


@pytest.mark.parametrize("name", sorted(set(NO_EVIDENCE) - {"unrelated"}))
def test_passcode_no_evidence(name):
    assert run(PASS, "isPasscodeCompliant", NO_EVIDENCE[name]) == (None, "error")


def test_compliance_zero_evaluated_is_unmeasured():
    assert run(PCT, "deviceCompliancePercentage", summary(0, 0, not_applicable=9)) == (None, "error")


def test_mdm_bool_counts_rejected():
    assert run(MDM, "isMdmManaged", overview(True, 0)) == (None, "error")


def test_passcode_paged_list_is_unmeasured():
    body = policies(IOS_ON)
    body["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?$skiptoken=x"
    assert run(PASS, "isPasscodeCompliant", body) == (None, "error")


def test_every_transform_reports_schema_version_2_0():
    """transformedResponse envelope is the CONTRIBUTING.md schemaVersion 2.0 one, on answers and on errors."""
    import importlib.util as iu
    for path in sorted(Path(__file__).parent.glob("*.py")):
        if path.name.startswith("test_"):
            continue
        spec = iu.spec_from_file_location("schema_" + path.stem, path)
        module = iu.module_from_spec(spec)
        spec.loader.exec_module(module)
        out = module.transform({})
        assert out["additionalInfo"]["metadata"]["schemaVersion"] == "2.0", path.name
        assert set(out["additionalInfo"]) == {"dataCollection", "validation", "transformation", "evaluation", "metadata"}
