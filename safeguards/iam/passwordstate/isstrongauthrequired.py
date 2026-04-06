"""
Transformation: isStrongAuthRequired
Vendor: Passwordstate
Category: Identity & Access Management

Evaluates isStrongAuthRequired for Passwordstate (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isStrongAuthRequired", "vendor": "Passwordstate", "category": "Identity & Access Management"}
        }
    }


def transform(input):
    criteriaKey = "isStrongAuthRequired"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        data = data.get("apiResponse", data)

        # ── EVALUATION LOGIC ──
        result = False

        users = data.get("data", data.get("users", []))
        if isinstance(data, list):
            users = data

        if isinstance(users, list) and len(users) > 0:
            mfa_count = 0
            total_active = 0
            for user in users:
                # Check if user is enabled
                is_enabled = user.get("EnableUser", user.get("IsEnabled", True))
                if not is_enabled:
                    continue
                total_active += 1
                # Check for MFA/2FA settings
                mfa_enabled = user.get("MFAEnabled", user.get("TwoFactorEnabled", False))
                auth_type = user.get("AuthenticationType", "")
                if mfa_enabled is True or str(mfa_enabled).lower() == "true":
                    mfa_count += 1
                elif isinstance(auth_type, str) and auth_type.lower() not in ("", "password", "windows"):
                    mfa_count += 1
            if total_active > 0:
                result = mfa_count >= total_active * 0.5
        # ── END EVALUATION LOGIC ──

        return create_response(

            result={"isStrongAuthRequired": result},

            validation=validation

        )
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
