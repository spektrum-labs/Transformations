"""
Transformation: isLifeCycleManagementEnabled
Vendor: Red Hat Idm
Category: Identity & Access Management

Evaluates isLifeCycleManagementEnabled for Red Hat IDM (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isLifeCycleManagementEnabled", "vendor": "Red Hat Idm", "category": "Identity & Access Management"}
        }
    }


def transform(input):
    criteriaKey = "isLifeCycleManagementEnabled"

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
            has_active = False
            has_disabled = False
            has_preserved = False

            for user in users:
                if isinstance(user, dict):
                    # IdM tracks nsaccountlock for disabled users
                    account_lock = user.get("nsaccountlock", user.get("accountLocked", False))
                    preserved = user.get("preserved", False)

                    if isinstance(account_lock, list):
                        account_lock = account_lock[0] if len(account_lock) > 0 else False

                    lock_str = str(account_lock).lower()
                    if lock_str in ["true", "1", "yes"]:
                        has_disabled = True
                    else:
                        has_active = True

                    if isinstance(preserved, list):
                        preserved = preserved[0] if len(preserved) > 0 else False
                    if str(preserved).lower() in ["true", "1", "yes"]:
                        has_preserved = True

            # Lifecycle management is evidenced by having users in different states
            if has_active and (has_disabled or has_preserved):
                result = True
            elif has_active and len(users) >= 2:
                # If multiple active users exist, basic lifecycle is in place
                result = True
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isLifeCycleManagementEnabled": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
