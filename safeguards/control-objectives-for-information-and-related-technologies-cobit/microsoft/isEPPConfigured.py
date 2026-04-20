"""
Transformation: isEPPConfigured
Vendor: Microsoft  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Whether device compliance policies with endpoint protection requirements are configured in Microsoft Intune.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Microsoft", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def check_policy_has_epp(policy):
    epp_fields = ["antivirusRequired", "antispywareRequired", "defenderEnabled", "defenderVersion",
                  "signatureOutOfDate", "realTimeProtectionEnabled", "deviceThreatProtectionEnabled"]
    for field in epp_fields:
        val = policy.get(field)
        if val is True or val == "required":
            return True
    return False


def evaluate(data):
    try:
        policies = data.get("value", [])
        total = len(policies)
        epp_policies = []
        for p in policies:
            if check_policy_has_epp(p):
                epp_policies.append(p.get("displayName", p.get("id", "unknown")))
        configured = len(epp_policies) > 0
        return {
            "isEPPConfigured": configured,
            "totalCompliancePolicies": total,
            "eppPolicyCount": len(epp_policies),
            "eppPolicyNames": epp_policies
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
            pass_reasons.append("Endpoint protection compliance policies are configured in Microsoft Intune")
            pass_reasons.append("EPP policies found: " + str(extra_fields.get("eppPolicyCount", 0)) + " of " + str(extra_fields.get("totalCompliancePolicies", 0)) + " total policies")
            epp_names = extra_fields.get("eppPolicyNames", [])
            if epp_names:
                pass_reasons.append("EPP policy names: " + ", ".join(epp_names))
        else:
            fail_reasons.append("No compliance policies with endpoint protection requirements found in Microsoft Intune")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create device compliance policies in Microsoft Intune requiring antivirusRequired, defenderEnabled, and realTimeProtectionEnabled")
        combined = {criteriaKey: result_value}
        for k in extra_fields:
            combined[k] = extra_fields[k]
        return create_response(
            result=combined, validation=validation,
            pass_reasons=pass_reasons, fail_reasons=fail_reasons, recommendations=recommendations,
            input_summary={criteriaKey: result_value, "totalCompliancePolicies": extra_fields.get("totalCompliancePolicies", 0), "eppPolicyCount": extra_fields.get("eppPolicyCount", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False}, validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)], fail_reasons=["Transformation error: " + str(e)])
