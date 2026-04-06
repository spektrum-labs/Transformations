"""
Transformation: isPAMEnabled
Vendor: Active Directory On Prem
Category: Identity & Access Management

Evaluates isPAMEnabled for Active Directory On-Prem (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPAMEnabled", "vendor": "Active Directory On Prem", "category": "Identity & Access Management"}
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

        users = data.get("users", data.get("data", data.get("value", [])))
        if isinstance(users, list) and len(users) > 0:
            total_count = len(users)
            # Identify privileged users by admin group membership or admin flag
            admin_users = []
            for user in users:
                is_admin = user.get("isAdmin", user.get("adminAccount", False))
                groups = user.get("memberOf", user.get("groups", []))
                if isinstance(groups, list):
                    admin_groups = [
                        g for g in groups
                        if any(keyword in str(g).lower() for keyword in ["domain admin", "enterprise admin", "schema admin", "administrator"])
                    ]
                    if admin_groups or is_admin:
                        admin_users.append(user)
                elif is_admin:
                    admin_users.append(user)

            # PAM is considered enabled if admin accounts exist and are limited
            # (less than 10% of total users or fewer than 10 admin accounts)
            if len(admin_users) > 0 and (len(admin_users) < total_count * 0.1 or len(admin_users) <= 10):
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
