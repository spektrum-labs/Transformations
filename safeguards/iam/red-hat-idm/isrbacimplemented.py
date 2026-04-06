"""
Transformation: isRBACImplemented
Vendor: Red Hat Idm
Category: Identity & Access Management

Evaluates isRBACImplemented for Red Hat IDM (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isRBACImplemented", "vendor": "Red Hat Idm", "category": "Identity & Access Management"}
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

        # role_find returns {"result": {"result": [...], "count": N}}
        roles = data.get("roles", [])
        total_count = data.get("totalCount", 0)

        if not roles and isinstance(data, dict):
            nested = data.get("result", data)
            if isinstance(nested, dict):
                nested = nested.get("result", nested)
            if isinstance(nested, list):
                roles = nested
            elif isinstance(nested, dict):
                roles = nested.get("result", [])
                total_count = nested.get("count", 0)

        if isinstance(roles, list) and len(roles) > 0:
            # Check for roles with actual member assignments
            roles_with_members = 0
            for role in roles:
                if isinstance(role, dict):
                    members = role.get("member_user", role.get("member_group", []))
                    privileges = role.get("memberof_privilege", [])
                    if (isinstance(members, list) and len(members) > 0) or (isinstance(privileges, list) and len(privileges) > 0):
                        roles_with_members = roles_with_members + 1
            result = roles_with_members > 0

            # If no member info, just verify roles exist
            if not result and len(roles) > 0:
                result = True

        if not result and isinstance(total_count, (int, float)) and total_count > 0:
            result = True
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isRBACImplemented": result, "roleCount": len(roles) if isinstance(roles, list) else total_count},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
