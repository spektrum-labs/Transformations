"""
Transformation: isPoliciesConfigured
Vendor: AppOmni  |  Category: Cloud Security
Evaluates: At least one enabled security policy exists in AppOmni
API: GET /api/v1/core/policy/
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return {"data": input_data["data"], "validation": input_data["validation"]}
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return {"data": data, "validation": {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}}


def str_to_bool(val):
    """Handle AppOmni string booleans ('True', 'False', 'None')."""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return False


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPoliciesConfigured", "vendor": "AppOmni", "category": "Cloud Security"}
        }
    }


def transform(input):
    criteriaKey = "isPoliciesConfigured"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        extracted = extract_input(input)
        data = extracted["data"]
        validation = extracted["validation"]

        # AppOmni /policy/ returns a paginated dict or bare list
        policies = []
        if isinstance(data, list):
            policies = [item for item in data if isinstance(item, dict)]
        elif isinstance(data, dict):
            candidate = data.get("results", data.get("data", data.get("items", None)))
            if isinstance(candidate, list):
                policies = [item for item in candidate if isinstance(item, dict)]
            else:
                policies = [data]

        total = len(policies)

        # A policy is considered enabled if its enabled field is true
        # AppOmni returns booleans as strings
        enabled = []
        for p in policies:
            if not isinstance(p, dict):
                continue
            if str_to_bool(p.get("active", p.get("enabled", False))):
                enabled.append(p)

        # Deduplicate policy types
        seen_types = {}
        policy_types = []
        for p in enabled:
            pt = p.get("policy_type", "")
            if pt and pt not in seen_types:
                seen_types[pt] = True
                policy_types.append(pt)

        result = len(enabled) >= 1

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result:
            type_str = ""
            for idx in range(len(policy_types)):
                if idx > 0:
                    type_str = type_str + ", "
                type_str = type_str + str(policy_types[idx])
            pass_reasons.append(str(len(enabled)) + " of " + str(total) + " policy/policies enabled")
            if policy_types:
                pass_reasons.append("Policy types: " + type_str)
        else:
            fail_reasons.append("No enabled policies found (total policies: " + str(total) + ")")
            recommendations.append("Configure and enable at least one security policy in AppOmni")

        return create_response(
            result={criteriaKey: result, "enabledPolicies": len(enabled), "totalPolicies": total, "policyTypes": policy_types},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalPolicies": total, "enabledPolicies": len(enabled), "policyTypes": policy_types}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
