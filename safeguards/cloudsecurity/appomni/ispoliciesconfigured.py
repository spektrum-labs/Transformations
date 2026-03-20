"""
Transformation: isPoliciesConfigured
Vendor: AppOmni  |  Category: Cloud Security
Evaluates: At least one enabled security policy exists in AppOmni
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
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
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


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

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # === EVALUATION LOGIC ===
        policies = data.get("results", data.get("data", data.get("items", [])))

        if not isinstance(policies, list):
            return create_response(
                result={criteriaKey: False, "enabledPolicies": 0, "totalPolicies": 0},
                validation=validation,
                fail_reasons=["Unexpected policies response format"],
                recommendations=["Verify the API response contains a list of policies"],
                input_summary={"dataType": "non-list"}
            )

        total = len(policies)

        enabled = [
            p for p in policies
            if p.get("enabled", False) is True or
               str(p.get("enabled", "")).lower() in ("true", "1", "yes")
        ]

        result = len(enabled) >= 1
        # === END EVALUATION LOGIC ===

        if result:
            pass_reasons.append(f"{len(enabled)} of {total} policy/policies enabled")
        else:
            fail_reasons.append(f"No enabled policies found (total policies: {total})")
            recommendations.append("Configure and enable at least one security policy in AppOmni")

        return create_response(
            result={criteriaKey: result, "enabledPolicies": len(enabled), "totalPolicies": total},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalPolicies": total, "enabledPolicies": len(enabled)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
