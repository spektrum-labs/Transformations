"""
Transformation: isPasscodeCompliant
Vendor: Microsoft Intune  |  Category: Mobile Security

Criterion: every Intune mobile compliance policy requires a device passcode.

Data source: getCompliancePolicies --
GET https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies
(https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list?view=graph-rest-1.0,
application permission DeviceManagementConfiguration.Read.All). Policies carry their derived @odata.type:
#microsoft.graph.iosCompliancePolicy -> passcodeRequired
(https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-ioscompliancepolicy?view=graph-rest-1.0),
#microsoft.graph.android*CompliancePolicy -> passwordRequired
(https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-androidcompliancepolicy?view=graph-rest-1.0).

  isPasscodeCompliant = at least one mobile policy exists AND every mobile policy requires a passcode.
  A tenant with no mobile compliance policy is a measured false (the list came back, it had none).

Not checked: policy assignment. Fails closed: an error body, no value list, or a paged list
(@odata.nextLink present, so some policies were not seen) returns None.
"""
import json
from datetime import datetime

KEY = "isPasscodeCompliant"
VENDOR = "Microsoft Intune"
CATEGORY = "Mobile Security"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": VENDOR, "category": CATEGORY},
        },
    }


def not_measured(reason, validation=None):
    return create_response(result={KEY: None}, validation=validation, api_errors=[reason], fail_reasons=[reason])


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float) and value == int(value) and value >= 0:
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def is_error_body(data):
    if not isinstance(data, dict):
        return False
    if data.get("error") or data.get("errors"):
        return True
    status = data.get("statusCode") or data.get("status_code") or data.get("status")
    if isinstance(status, int) and status >= 400:
        return True
    return False


def load(input):
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        input = json.loads(input) if input.strip() else None
    return extract_input(input)


def platform(policy):
    kind = str(policy.get("@odata.type") or "").lower()
    if "ioscompliancepolicy" in kind:
        return "ios"
    if "android" in kind and "compliancepolicy" in kind:
        return "android"
    return None


def transform(input):
    try:
        data, validation = load(input)
        if is_error_body(data):
            return not_measured("Microsoft Graph returned an error for deviceCompliancePolicies", validation)
        policies = data.get("value") if isinstance(data, dict) else None
        if not isinstance(policies, list):
            return not_measured("No deviceCompliancePolicies list was returned", validation)
        if data.get("@odata.nextLink"):
            return not_measured("The policy list is paged and only the first page was read", validation)
        mobile = 0
        requiring = 0
        missing = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            kind = platform(policy)
            if kind is None:
                continue
            mobile = mobile + 1
            flag = policy.get("passcodeRequired") if kind == "ios" else policy.get("passwordRequired")
            if flag is True:
                requiring = requiring + 1
            else:
                missing.append(str(policy.get("displayName") or policy.get("id") or "unnamed policy"))
        result = {KEY: mobile > 0 and requiring == mobile, "mobileCompliancePolicyCount": mobile,
                  "policiesRequiringPasscode": requiring, "totalCompliancePolicyCount": len(policies)}
        if mobile == 0:
            return create_response(result=result, validation=validation, input_summary=result,
                                   fail_reasons=["No iOS or Android compliance policy exists in Intune"],
                                   recommendations=["Create iOS and Android compliance policies that require a passcode"])
        line = str(requiring) + " of " + str(mobile) + " mobile compliance policies require a passcode"
        if requiring == mobile:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=result)
        return create_response(result=result, validation=validation, input_summary=result,
                               fail_reasons=[line + "; not required by: " + ", ".join(missing)],
                               recommendations=["Set passcodeRequired / passwordRequired on every mobile compliance policy"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
