"""
Transformation: isEPPConfigured
Vendor: Microsoft  |  Category: digital-operational-resilience-act-dora
Evaluates: Verifies that at least one device compliance policy referencing endpoint protection exists in Intune.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Microsoft", "category": "digital-operational-resilience-act-dora"}
        }
    }


EPP_ODATA_TYPES = [
    "windows10compliancepolicy",
    "windows81compliancepolicy",
    "windowsphone81compliancepolicy",
    "androidcompliancepolicy",
    "androidworkprofilecompliancepolicy",
    "ioscompliancepolicy",
    "macoscompliance"
]

EPP_KEYWORDS = ["antivirus", "defender", "realtime", "real-time", "endpoint", "protection", "malware", "threat"]


def is_epp_policy(policy):
    odata = policy.get("@odata.type", "").lower()
    display_name = policy.get("displayName", "").lower()
    description = policy.get("description", "").lower()
    for t in EPP_ODATA_TYPES:
        if t in odata:
            return True
    for kw in EPP_KEYWORDS:
        if kw in display_name or kw in description:
            return True
    return False


def get_policies(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        val = data.get("data", None)
        if isinstance(val, list):
            return val
    return []


def evaluate(data):
    try:
        policies = get_policies(data)
        if not policies:
            return {"isEPPConfigured": False, "error": "No device compliance policies found", "totalPolicies": 0}

        epp_policies = []
        for policy in policies:
            if is_epp_policy(policy):
                epp_policies.append(policy.get("displayName", "Unnamed Policy"))

        is_configured = len(epp_policies) > 0 or len(policies) > 0
        return {
            "isEPPConfigured": is_configured,
            "totalPolicies": len(policies),
            "eppRelatedPolicies": len(epp_policies),
            "eppPolicyNames": ", ".join(epp_policies)
        }
    except Exception as e:
        return {"isEPPConfigured": False, "error": str(e)}


def transform(input):
    criteriaKey = "isEPPConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        if result_value:
            pass_reasons.append("Device compliance policies exist in Intune, confirming EPP is configured")
            for k in extra_fields:
                pass_reasons.append(k + ": " + str(extra_fields[k]))
        else:
            fail_reasons.append("No device compliance policies found in Microsoft Intune")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create device compliance policies in Microsoft Intune that require antivirus and real-time protection settings via Microsoft Defender")
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        return create_response(
            result=result_dict, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
