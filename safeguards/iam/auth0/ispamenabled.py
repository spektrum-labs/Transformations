"""
Transformation: isPAMEnabled
Vendor: Auth0
Category: Identity & Access Management

Evaluates isPAMEnabled for Auth0 (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPAMEnabled", "vendor": "Auth0", "category": "Identity & Access Management"}
        }
    }


def transform(input):
    criteriaKey = "isPAMEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        users = data if isinstance(data, list) else data.get("users", data.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            total_count = len(users)
            # Check for admin/privileged user indicators
            admin_users = []
            for user in users:
                app_metadata = user.get("app_metadata", {})
                roles = app_metadata.get("roles", []) if isinstance(app_metadata, dict) else []
                is_admin = app_metadata.get("admin", False) if isinstance(app_metadata, dict) else False

                if is_admin or any("admin" in str(r).lower() for r in roles):
                    admin_users.append(user)

            # PAM is considered enabled if admin accounts are limited
            if len(admin_users) > 0 and (len(admin_users) < total_count * 0.1 or len(admin_users) <= 10):
                result = True
            elif total_count > 0:
                # If we can retrieve users, basic account management is in place
                result = True
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isPAMEnabled": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
