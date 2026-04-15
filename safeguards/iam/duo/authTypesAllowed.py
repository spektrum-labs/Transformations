"""
Transformation: authTypesAllowed
Vendor: Duo  |  Category: IAM
Evaluates: Validates which authentication factor types are permitted in the Duo account and
that only approved strong authentication methods are enabled (e.g. push, hardware tokens,
TOTP). Weak or legacy methods (SMS passcodes, phone callback) should not be the only
options available.
"""
import json
from datetime import datetime


STRONG_AUTH_METHODS = ["push", "u2f", "token", "webauthn", "duo_push", "hardware_token", "totp"]
WEAK_AUTH_METHODS = ["sms", "phone", "bypass"]


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
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
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "authTypesAllowed",
                "vendor": "Duo",
                "category": "IAM"
            }
        }
    }


def evaluate(data):
    """
    Duo Admin API /admin/v1/settings returns a dict. Relevant fields for auth types:
      allowed_auth_types  (list of strings or comma-separated string)
      sms_batch           (bool/int)
      telephony_warning_min (int)

    Passes if at least one strong method is allowed and SMS/phone are not the sole methods.
    Falls back to Duo defaults (push, token, phone, sms) if no explicit field is present.
    """
    criteriaKey = "authTypesAllowed"
    try:
        settings = data
        if not isinstance(settings, dict):
            return {criteriaKey: False, "error": "Settings data is not a dict"}

        allowed_raw = settings.get("allowed_auth_types", None)
        allowed_types = []
        allowed_types_inferred = False

        if isinstance(allowed_raw, list):
            allowed_types = [str(x).lower() for x in allowed_raw]
        elif isinstance(allowed_raw, str) and allowed_raw:
            allowed_types = [x.strip().lower() for x in allowed_raw.split(",")]

        # Infer from individual feature flags if no explicit list
        if not allowed_types:
            allowed_types_inferred = True
            sms_enabled = settings.get("sms_batch", 0)
            if sms_enabled:
                allowed_types.append("sms")
            # Duo default: push and token are always available unless explicitly disabled
            allowed_types.append("push")
            allowed_types.append("token")

        # Classify methods
        strong_allowed = [m for m in allowed_types if m in STRONG_AUTH_METHODS]
        weak_allowed = [m for m in allowed_types if m in WEAK_AUTH_METHODS]

        has_strong = len(strong_allowed) > 0
        only_weak = (not has_strong) and len(weak_allowed) > 0

        result_value = has_strong

        auth_type_failures = []
        if only_weak:
            auth_type_failures.append("Only weak authentication methods are permitted: " + ", ".join(weak_allowed))
        if not has_strong and not only_weak:
            auth_type_failures.append("No authentication methods could be determined from the settings response")

        return {
            criteriaKey: result_value,
            "allowedAuthTypes": allowed_types,
            "strongMethodsAllowed": strong_allowed,
            "weakMethodsAllowed": weak_allowed,
            "hasStrongAuthMethod": has_strong,
            "onlyWeakMethodsAllowed": only_weak,
            "dataInferred": allowed_types_inferred,
            "authTypeFailures": auth_type_failures
        }

    except Exception as e:
        return {criteriaKey: False, "error": str(e)}


def transform(input):
    criteriaKey = "authTypesAllowed"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        auth_type_failures = eval_result.get("authTypeFailures", [])

        extra_fields = {}
        skip_keys = [criteriaKey, "error", "authTypeFailures"]
        for k in eval_result:
            if k not in skip_keys:
                extra_fields[k] = eval_result[k]

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        strong_methods = extra_fields.get("strongMethodsAllowed", [])
        weak_methods = extra_fields.get("weakMethodsAllowed", [])
        allowed = extra_fields.get("allowedAuthTypes", [])
        inferred = extra_fields.get("dataInferred", False)

        if result_value:
            pass_reasons.append("At least one strong authentication method is permitted: " + ", ".join(strong_methods))
            if weak_methods:
                additional_findings.append("Weak methods are also permitted alongside strong methods: " + ", ".join(weak_methods))
                recommendations.append("Consider disabling SMS and phone callback authentication methods in Duo Admin Panel under Settings > Authentication Methods to enforce phishing-resistant MFA only")
            if inferred:
                additional_findings.append("Authentication type data was inferred from settings flags; no explicit allowed_auth_types field was found in the API response")
            additional_findings.append("Full list of allowed authentication types: " + ", ".join(allowed))
        else:
            if "error" in eval_result:
                fail_reasons.append("Evaluation error: " + eval_result["error"])
            else:
                fail_reasons.append("No strong authentication methods are configured as allowed in Duo account settings")
                for af in auth_type_failures:
                    fail_reasons.append(af)
            recommendations.append("Enable strong authentication methods (Duo Push, hardware tokens, WebAuthn) in Duo Admin Panel under Settings > Authentication Methods")
            recommendations.append("Disable or restrict weak methods such as SMS passcodes and phone callbacks")
            if inferred:
                additional_findings.append("Authentication type data was inferred from settings flags; review allowed_auth_types in the Duo Admin Panel directly")

        combined_result = {criteriaKey: result_value}
        for k in extra_fields:
            combined_result[k] = extra_fields[k]

        combined_summary = {criteriaKey: result_value}
        combined_summary["allowedAuthTypes"] = allowed
        combined_summary["strongMethodsAllowed"] = strong_methods
        combined_summary["weakMethodsAllowed"] = weak_methods

        return create_response(
            result=combined_result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=combined_summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
