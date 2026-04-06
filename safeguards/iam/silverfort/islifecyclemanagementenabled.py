"""
Transformation: isLifeCycleManagementEnabled
Vendor: Silverfort
Category: Identity & Access Management

Evaluates isLifeCycleManagementEnabled for Silverfort (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isLifeCycleManagementEnabled", "vendor": "Silverfort", "category": "Identity & Access Management"}
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

        users = data.get("users", data)
        if isinstance(users, dict):
            users = users.get("items", users.get("data", []))

        if isinstance(users, list) and len(users) > 0:
            statuses = set()
            has_risk_tracking = False

            for user in users:
                if isinstance(user, dict):
                    status = str(user.get("status", user.get("state", ""))).lower()
                    if len(status) > 0:
                        statuses.add(status)

                    # Risk tracking indicates active monitoring/governance
                    risk = user.get("risk", user.get("riskLevel", user.get("riskScore", None)))
                    if risk is not None:
                        has_risk_tracking = True

                    # Check for last activity timestamps (indicates monitoring)
                    last_seen = user.get("lastSeen", user.get("lastActivity", None))
                    if last_seen is not None:
                        has_risk_tracking = True

            if has_risk_tracking:
                result = True
            elif len(statuses) > 1:
                result = True
            elif len(users) >= 2:
                # Silverfort provides continuous identity protection
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
