"""
Transformation: isEPPConfigured
Vendor: Sophos  |  Category: control-objectives-for-information-and-related-technologies-cobit
Evaluates: Verify a Threat Protection policy is properly configured and enabled, confirming
EPP is configured to vendor guidance via getEndpointPolicies.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isEPPConfigured", "vendor": "Sophos", "category": "control-objectives-for-information-and-related-technologies-cobit"}
        }
    }


def evaluate(data):
    try:
        items = data.get("items", [])
        total_policies = len(items)
        threat_protection_policies = [item for item in items if item.get("type") == "threat-protection"]
        enabled_policies = [p for p in threat_protection_policies if p.get("enabled") == True]
        policy_names = [p.get("name", "unnamed") for p in enabled_policies]
        is_configured = len(enabled_policies) > 0
        return {
            "isEPPConfigured": is_configured,
            "totalPolicies": total_policies,
            "threatProtectionPolicies": len(threat_protection_policies),
            "enabledThreatProtectionPolicies": len(enabled_policies),
            "enabledPolicyNames": policy_names
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
        result_dict = {criteriaKey: result_value}
        for k in extra_fields:
            result_dict[k] = extra_fields[k]
        if result_value:
            pass_reasons.append("At least one enabled threat-protection policy is configured")
            pass_reasons.append("enabledThreatProtectionPolicies: " + str(extra_fields.get("enabledThreatProtectionPolicies", 0)))
            names = extra_fields.get("enabledPolicyNames", [])
            if names:
                pass_reasons.append("Policies: " + ", ".join(names))
        else:
            fail_reasons.append("No enabled threat-protection policy found in endpoint policies")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append("Create and enable a Threat Protection policy in Sophos Central and apply it to your endpoint groups")
        return create_response(
            result=result_dict,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalPolicies": extra_fields.get("totalPolicies", 0), "enabledThreatProtectionPolicies": extra_fields.get("enabledThreatProtectionPolicies", 0)})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
