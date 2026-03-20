"""
Transformation: isSSOEnforced
Vendor: AppOmni  |  Category: Cloud Security
Evaluates: SSO/SAML is enabled AND enforced (local login disabled) for AppOmni access
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isSSOEnforced", "vendor": "AppOmni", "category": "Cloud Security"}
        }
    }


def transform(input):
    criteriaKey = "isSSOEnforced"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation, fail_reasons=["Input validation failed"])

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # === EVALUATION LOGIC ===
        def to_bool(val):
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ("true", "1", "yes", "enabled")
            return bool(val)

        sso_enabled = to_bool(data.get("sso_enabled", False))
        sso_enforced = to_bool(
            data.get("sso_enforced", data.get("enforce_sso", False))
        )
        # local_login_allowed defaults to True (unsafe) when absent -- conservative
        local_login_allowed = to_bool(data.get("local_login_allowed", True))
        sso_provider = data.get("sso_provider", data.get("provider", "unknown"))

        # All three conditions required:
        # 1. SSO is configured
        # 2. SSO is enforced (required, not optional)
        # 3. Local login backdoor is disabled
        result = sso_enabled and sso_enforced and not local_login_allowed
        # === END EVALUATION LOGIC ===

        if result:
            pass_reasons.append("SSO is enabled, enforced, and local login is disabled")
            if sso_provider != "unknown":
                pass_reasons.append(f"SSO provider: {sso_provider}")
        else:
            if not sso_enabled:
                fail_reasons.append("SSO is not enabled")
                recommendations.append("Enable SSO/SAML authentication in AppOmni")
            if not sso_enforced:
                fail_reasons.append("SSO is not enforced")
                recommendations.append("Enforce SSO so users cannot bypass it")
            if local_login_allowed:
                fail_reasons.append("Local login is still allowed")
                recommendations.append("Disable local login to prevent SSO bypass")

        return create_response(
            result={criteriaKey: result, "ssoProvider": sso_provider, "localLoginAllowed": local_login_allowed},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"ssoEnabled": sso_enabled, "ssoEnforced": sso_enforced, "localLoginAllowed": local_login_allowed, "ssoProvider": sso_provider}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
