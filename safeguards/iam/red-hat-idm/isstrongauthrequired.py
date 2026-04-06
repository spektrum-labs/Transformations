"""
Transformation: isStrongAuthRequired
Vendor: Red Hat Idm
Category: Identity & Access Management

Evaluates isStrongAuthRequired for Red Hat IDM (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isStrongAuthRequired", "vendor": "Red Hat Idm", "category": "Identity & Access Management"}
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

        # config_show returns global IdM config with ipauserauthtype
        config = data.get("config", data)
        if isinstance(config, dict):
            config = config.get("result", config)

        auth_types = []
        if isinstance(config, dict):
            auth_types = config.get("ipauserauthtype", config.get("authTypes", []))

        if isinstance(auth_types, list):
            strong_types = ["otp", "radius", "pkinit", "idp"]
            for auth_type in auth_types:
                if isinstance(auth_type, str) and auth_type.lower() in strong_types:
                    result = True
                    break
        elif isinstance(auth_types, str) and auth_types.lower() in ["otp", "radius", "pkinit", "idp"]:
            result = True

        # Also check policies array if present
        policies = data.get("policies", [])
        if isinstance(policies, list) and not result:
            for policy in policies:
                if isinstance(policy, dict):
                    policy_type = policy.get("type", "").lower()
                    if "mfa" in policy_type or "otp" in policy_type:
                        result = True
                        break
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
