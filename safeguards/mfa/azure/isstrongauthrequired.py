"""
Transformation: isStrongAuthRequired
Vendor: Azure / Microsoft Entra ID
Category: Identity / Authentication

Evaluates if strong (phishing-resistant) authentication methods are enabled
by inspecting the Microsoft Graph authenticationMethodsPolicy response.

Strong auth methods: MicrosoftAuthenticator, Fido2
Weak auth methods: Sms, Voice, Email, SoftwareOath

API: GET /v1.0/policies/authenticationMethodsPolicy
Reference: https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get
"""

import json
from datetime import datetime

STRONG_AUTH_METHODS = {
    "Fido2": "FIDO2 Security Key",
    "MicrosoftAuthenticator": "Microsoft Authenticator",
}

WEAK_AUTH_METHODS = {
    "Sms": "SMS",
    "Voice": "Voice call",
    "Email": "Email OTP",
    "SoftwareOath": "Software OATH token",
}


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return {"data": input_data["data"], "validation": input_data["validation"]}
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return {"data": data, "validation": {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
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
                "transformationId": "isStrongAuthRequired",
                "vendor": "Azure",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isStrongAuthRequired"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        extracted = extract_input(input)
        data = extracted["data"]
        validation = extracted["validation"]

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        # Extract authenticationMethodConfigurations from the policy response
        configs = []
        if isinstance(data, dict):
            configs = data.get("authenticationMethodConfigurations", [])
            if not isinstance(configs, list):
                configs = []
        elif isinstance(data, list):
            configs = data

        enabled_strong = []
        disabled_strong = []
        enabled_weak = []

        for config in configs:
            if not isinstance(config, dict):
                continue
            method_id = config.get("id", "")
            state = (config.get("state", "") or "").lower()

            if method_id in STRONG_AUTH_METHODS:
                label = STRONG_AUTH_METHODS[method_id]
                if state == "enabled":
                    enabled_strong.append(label)
                else:
                    disabled_strong.append(label)
            elif method_id in WEAK_AUTH_METHODS:
                label = WEAK_AUTH_METHODS[method_id]
                if state == "enabled":
                    enabled_weak.append(label)

        is_required = len(enabled_strong) > 0

        if is_required:
            strong_str = ", ".join(enabled_strong)
            pass_reasons.append("Strong authentication method(s) enabled: " + strong_str)
            if disabled_strong:
                additional_findings.append("Strong method(s) not yet enabled: " + ", ".join(disabled_strong))
        else:
            fail_reasons.append("No strong authentication methods (Authenticator or FIDO2) are enabled")
            recommendations.append("Enable Microsoft Authenticator and/or FIDO2 security keys in the authentication methods policy")

        if enabled_weak:
            additional_findings.append("Weak authentication method(s) still enabled: " + ", ".join(enabled_weak))
            recommendations.append("Consider disabling weak methods (" + ", ".join(enabled_weak) + ") to enforce phishing-resistant authentication")

        return create_response(
            result={
                criteriaKey: is_required,
                "enabledStrongMethods": enabled_strong,
                "enabledWeakMethods": enabled_weak,
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary={
                "totalMethods": len(configs),
                "enabledStrongCount": len(enabled_strong),
                "disabledStrongCount": len(disabled_strong),
                "enabledWeakCount": len(enabled_weak),
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)]
        )
