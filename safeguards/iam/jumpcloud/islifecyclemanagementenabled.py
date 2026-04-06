"""
Transformation: isLifeCycleManagementEnabled
Vendor: Jumpcloud
Category: Identity & Access Management

Evaluates isLifeCycleManagementEnabled for JumpCloud (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isLifeCycleManagementEnabled", "vendor": "Jumpcloud", "category": "Identity & Access Management"}
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

        users = data.get("results", data.get("users", []))
        if isinstance(users, list) and len(users) > 0:
            # Check for lifecycle indicators: suspended users, locked accounts,
            # or users with activation/created timestamps
            managed_count = 0
            for user in users:
                state = user.get("state", "")
                account_locked = user.get("account_locked", False)
                suspended = user.get("suspended", False)
                created = user.get("created", user.get("_created", ""))
                if state in ("SUSPENDED", "STAGED", "LOCKED_OUT"):
                    managed_count += 1
                elif account_locked is True or suspended is True:
                    managed_count += 1
                elif created:
                    managed_count += 1
            # If users have lifecycle attributes, management is enabled
            result = managed_count > 0
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
