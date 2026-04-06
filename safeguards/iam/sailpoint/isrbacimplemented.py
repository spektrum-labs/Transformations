"""
Transformation: isRBACImplemented
Vendor: Sailpoint
Category: Identity & Access Management

Evaluates isRBACImplemented for SailPoint IdentityNow (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRBACImplemented", "vendor": "Sailpoint", "category": "Identity & Access Management"}
        }
    }


def transform(input):
    criteriaKey = "isRBACImplemented"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        roles = data.get("roles", data)
        if isinstance(roles, dict):
            roles = roles.get("items", roles.get("data", []))

        if isinstance(roles, list) and len(roles) > 0:
            roles_with_profiles = 0
            for role in roles:
                if isinstance(role, dict):
                    access_profiles = role.get("accessProfiles", role.get("entitlements", []))
                    enabled = role.get("enabled", role.get("active", True))
                    if isinstance(access_profiles, list) and len(access_profiles) > 0:
                        roles_with_profiles = roles_with_profiles + 1
                    elif enabled:
                        roles_with_profiles = roles_with_profiles + 1

            result = roles_with_profiles > 0
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isRBACImplemented": result, "roleCount": len(roles) if isinstance(roles, list) else 0},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
