"""
Transformation: isPAMEnabled
Vendor: Red Hat Idm
Category: Identity & Access Management

Evaluates isPAMEnabled for Red Hat IDM (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isPAMEnabled", "vendor": "Red Hat Idm", "category": "Identity & Access Management"}
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

        users = data.get("users", [])
        if not users and isinstance(data, dict):
            nested = data.get("result", data)
            if isinstance(nested, dict):
                nested = nested.get("result", nested)
            if isinstance(nested, list):
                users = nested

        if isinstance(users, list) and len(users) > 0:
            admin_users = []
            regular_users = []
            for user in users:
                if isinstance(user, dict):
                    groups = user.get("memberof_group", user.get("groups", []))
                    uid = user.get("uid", user.get("login", [""]))[0] if isinstance(user.get("uid", user.get("login", "")), list) else user.get("uid", user.get("login", ""))
                    is_admin = False

                    if isinstance(groups, list):
                        for group in groups:
                            group_str = str(group).lower()
                            if "admin" in group_str or "sudo" in group_str or "wheel" in group_str:
                                is_admin = True
                                break

                    if is_admin:
                        admin_users.append(uid)
                    else:
                        regular_users.append(uid)

            # PAM is considered enabled if there are dedicated admin accounts
            # and they are separate from regular user accounts
            if len(admin_users) > 0 and len(regular_users) > 0:
                result = True
            elif len(admin_users) > 0:
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
