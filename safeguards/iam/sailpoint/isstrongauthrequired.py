"""
Transformation: isStrongAuthRequired
Vendor: Sailpoint
Category: Identity & Access Management

Evaluates isStrongAuthRequired for SailPoint IdentityNow (IAM)
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isStrongAuthRequired", "vendor": "Sailpoint", "category": "Identity & Access Management"}
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

        mfa_config = data.get("mfaConfig", data)
        if isinstance(mfa_config, dict):
            # Check for any enabled MFA method
            enabled = mfa_config.get("enabled", mfa_config.get("mfaEnabled", None))
            if isinstance(enabled, bool) and enabled:
                result = True

            # Check individual MFA methods
            methods = mfa_config.get("methods", mfa_config.get("factors", []))
            if isinstance(methods, list):
                for method in methods:
                    if isinstance(method, dict) and method.get("enabled", False):
                        result = True
                        break

            # Check duo, okta-verify, etc.
            for key in ["duo", "okta", "google", "sms", "email", "totp"]:
                method_cfg = mfa_config.get(key, {})
                if isinstance(method_cfg, dict) and method_cfg.get("enabled", False):
                    result = True
                    break

        # Check if response is a list of MFA configs
        if isinstance(mfa_config, list):
            for cfg in mfa_config:
                if isinstance(cfg, dict) and cfg.get("enabled", False):
                    result = True
                    break

        # Check policies array
        policies = data.get("policies", [])
        if isinstance(policies, list) and not result:
            for policy in policies:
                if isinstance(policy, dict):
                    action = policy.get("action", "").lower()
                    if "mfa" in action or "step_up" in action:
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
