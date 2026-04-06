"""
Transformation: isRBACImplemented
Vendor: Strongdm
Category: Identity & Access Management

Evaluates isRBACImplemented for StrongDM (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRBACImplemented", "vendor": "Strongdm", "category": "Identity & Access Management"}
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
        total = data.get("totalCount", data.get("meta", {}).get("total", 0))

        if isinstance(roles, dict):
            roles = roles.get("items", roles.get("data", []))

        if isinstance(roles, list) and len(roles) > 0:
            roles_with_grants = 0
            for role in roles:
                if isinstance(role, dict):
                    # Check for resource grants
                    grants = role.get("accessRules", role.get("grants", role.get("resources", [])))
                    name = role.get("name", role.get("displayName", ""))
                    managed = role.get("managed", role.get("composite", False))

                    if isinstance(grants, list) and len(grants) > 0:
                        roles_with_grants = roles_with_grants + 1
                    elif isinstance(name, str) and len(name) > 0:
                        roles_with_grants = roles_with_grants + 1

            result = roles_with_grants > 0

        if not result and isinstance(total, (int, float)) and total > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isRBACImplemented": result, "roleCount": len(roles) if isinstance(roles, list) else total},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
