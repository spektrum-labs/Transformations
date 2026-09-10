"""
Transformation: authTypesAllowed
Vendor: Generic IDP
Category: Identity / Authentication

Returns a list of Authenticator Types that are active and evaluates whether every
active type is an allowed one.

The allowlist is written against the factorType strings Okta actually emits. It
previously tested for the literal strings "fido" and "otp", which no Okta org
ever returns: real FIDO2 arrives as webauthn, U2F as u2f and Okta FastPass as
signed_nonce, so all three failed a check named "Only FIDO or OTP allowed".
Okta Verify push (push) failed for the same reason.

Two further defects fixed here:
  - sms was skipped before the allowlist ran, so an org with SMS enabled passed
    a check whose own description says it denies SMS.
  - an empty or non-list payload passed with "No insecure authentication types
    found", which made the check green off zero data.
"""

import json
from datetime import datetime

# factorType values Okta emits that are acceptable as a second factor:
# FIDO2/WebAuthn, legacy FIDO U2F, Okta FastPass, Okta Verify push, and an
# authenticator app TOTP code. Every other active factorType fails, including
# sms, call, email and question.
ALLOWED_FACTOR_TYPES = ["webauthn", "u2f", "signed_nonce", "push", "token:software:totp"]

# Display label only, preserved from the previous version so the rendered
# authTypes list does not change shape for factors that already passed.
DISPLAY_LABELS = {"token:software:totp": "OTP"}


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
                # Handle list in response wrapper
                if key in data and isinstance(data.get(key), list):
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
                "transformationId": "authTypesAllowed",
                "vendor": "Generic",
                "category": "Identity"
            }
        }
    }


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
                result={criteriaKey: False, "authTypes": []},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # A payload carrying no factors cannot evidence anything. This used to
        # fall through to "No insecure authentication types found" and pass.
        if not isinstance(data, list) or len(data) == 0:
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation=validation,
                fail_reasons=["No authenticator types returned by the identity provider"],
                recommendations=["Verify the integration can read the organization's authenticator configuration"],
                input_summary={"totalAuthTypes": 0, "secureAuthTypes": 0, "insecureAuthTypes": 0}
            )

        # Classify on the raw factorType; label only for display. sms is no
        # longer skipped, so it reaches the allowlist and fails.
        activeFactorTypes = []
        authTypes = []
        for item in data:
            if isinstance(item, dict) and str(item.get('status', '')).lower() == 'active':
                factor_type = str(item.get('factorType', ''))
                if factor_type:
                    activeFactorTypes.append(factor_type)
                    authTypes.append(DISPLAY_LABELS.get(factor_type.lower(), factor_type))

        if len(activeFactorTypes) == 0:
            return create_response(
                result={criteriaKey: False, "authTypes": []},
                validation=validation,
                fail_reasons=["No active authenticator types are enabled"],
                recommendations=["Enable an allowed authenticator type"],
                input_summary={"totalAuthTypes": 0, "secureAuthTypes": 0, "insecureAuthTypes": 0}
            )

        secureFactorTypes = [f for f in activeFactorTypes if f.lower() in ALLOWED_FACTOR_TYPES]
        otherAuthTypes = [f for f in activeFactorTypes if f.lower() not in ALLOWED_FACTOR_TYPES]

        is_allowed = len(otherAuthTypes) == 0

        if is_allowed:
            pass_reasons.append(f"Only allowed authentication types are active: {', '.join(authTypes)}")
        else:
            fail_reasons.append(f"Authentication types that are not allowed are active: {', '.join(otherAuthTypes)}")
            recommendations.append("Restrict authentication to FIDO2/WebAuthn, U2F, Okta FastPass, Okta Verify push or an authenticator app code")

        return create_response(
            result={criteriaKey: is_allowed, "authTypes": authTypes},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalAuthTypes": len(activeFactorTypes),
                "secureAuthTypes": len(secureFactorTypes),
                "insecureAuthTypes": len(otherAuthTypes)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "authTypes": []},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
