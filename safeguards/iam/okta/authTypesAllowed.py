"""
Transformation: authTypesAllowed
Vendor: Okta  |  Category: iam
Evaluates: Lists all authenticators from /api/v1/authenticators and returns the set of
ACTIVE authenticator types (e.g. TOTP, push, SMS, WebAuthn) configured as allowed in
the org.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for loop_iter in range(3):
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
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "authTypesAllowed", "vendor": "Okta", "category": "iam"}
        }
    }


def get_authenticators_list(data):
    """Extract the list of authenticators from the data regardless of shape."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ["getAuthenticators", "authenticators"]:
            if key in data and isinstance(data[key], list):
                return data[key]
        for key in data:
            val = data[key]
            if isinstance(val, list) and len(val) > 0:
                first = val[0]
                if isinstance(first, dict) and ("key" in first or "type" in first):
                    return val
    return []


def deduplicate(items):
    """Return a list with duplicates removed while preserving order."""
    seen = {}
    result = []
    for item in items:
        if item not in seen:
            seen[item] = True
            result.append(item)
    return result


def evaluate(data):
    """Extract and categorize all ACTIVE authenticators from the Okta authenticators API."""
    try:
        authenticators = get_authenticators_list(data)
        total_authenticators = len(authenticators)
        active_authenticators = [a for a in authenticators if a.get("status", "") == "ACTIVE"]
        inactive_authenticators = [a for a in authenticators if a.get("status", "") != "ACTIVE"]

        active_types = deduplicate([a.get("type", "UNKNOWN") for a in active_authenticators if a.get("type", "")])
        active_keys = deduplicate([a.get("key", "") for a in active_authenticators if a.get("key", "")])
        active_names = deduplicate([a.get("name", "") for a in active_authenticators if a.get("name", "")])
        inactive_names = deduplicate([a.get("name", "") for a in inactive_authenticators if a.get("name", "")])

        has_active = len(active_authenticators) > 0
        has_mfa_type = any(
            t in ["token:software:totp", "signed_nonce", "webauthn", "push", "phone", "sms", "email", "okta_verify"]
            for t in active_keys
        )

        return {
            "authTypesAllowed": has_active,
            "activeAuthenticatorTypes": active_types,
            "activeAuthenticatorKeys": active_keys,
            "activeAuthenticatorNames": active_names,
            "inactiveAuthenticatorNames": inactive_names,
            "totalAuthenticatorsCount": total_authenticators,
            "activeAuthenticatorsCount": len(active_authenticators),
            "hasMFACapableAuthenticator": has_mfa_type
        }
    except Exception as e:
        return {"authTypesAllowed": False, "error": str(e)}


def transform(input):
    criteriaKey = "authTypesAllowed"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            return create_response(result={criteriaKey: False}, validation=validation,
                                   fail_reasons=["Input validation failed"])
        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []
        active_count = extra_fields.get("activeAuthenticatorsCount", 0)
        active_types = extra_fields.get("activeAuthenticatorTypes", [])
        active_names = extra_fields.get("activeAuthenticatorNames", [])
        has_mfa = extra_fields.get("hasMFACapableAuthenticator", False)
        inactive_names = extra_fields.get("inactiveAuthenticatorNames", [])
        if result_value:
            pass_reasons.append(str(active_count) + " active authenticator(s) are configured in the Okta org.")
            if active_types:
                pass_reasons.append("Active authenticator types: " + ", ".join(active_types))
            if has_mfa:
                pass_reasons.append("At least one MFA-capable authenticator is active (e.g. TOTP, WebAuthn, push, phone).")
        else:
            fail_reasons.append("No active authenticators were found in the Okta org.")
            if "error" in eval_result:
                fail_reasons.append("Error: " + eval_result["error"])
            recommendations.append("Activate at least one authenticator in the Okta Admin Console under Security > Authenticators.")
        if active_names:
            additional_findings.append("Active authenticators: " + ", ".join(active_names))
        if inactive_names:
            additional_findings.append("Inactive authenticators: " + ", ".join(inactive_names))
        additional_findings.append("Total authenticators returned: " + str(extra_fields.get("totalAuthenticatorsCount", 0)))
        if not has_mfa and result_value:
            recommendations.append("Consider enabling MFA-capable authenticators (TOTP, WebAuthn, push) in addition to password-only factors.")
        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={criteriaKey: result_value, "activeAuthenticatorsCount": active_count, "activeAuthenticatorTypes": active_types})
    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)])
