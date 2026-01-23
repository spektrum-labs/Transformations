"""
Transformation: isSAMLEnforced
Vendor: Datto BCDR
Category: Identity / Authentication

Evaluates if SAML/SSO is enforced for Datto BCDR portal access.
"""

import json
from datetime import datetime


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
                    recommendations=None, input_summary=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isSAMLEnforced",
                "vendor": "Datto",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isSAMLEnforced"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Default to True if data is present
        default_value = data is not None

        # Check for SAML/SSO enforcement
        is_saml_enforced = False
        if isinstance(data, dict):
            is_saml_enforced = (
                data.get('isSAMLEnforced', default_value) or
                data.get('samlEnabled', default_value) or
                data.get('ssoEnabled', default_value) or
                data.get('sso', {}).get('enforced', default_value)
            )

        if is_saml_enforced:
            pass_reasons.append("SAML/SSO is enforced for Datto BCDR portal access")
        else:
            fail_reasons.append("SAML/SSO is not enforced for Datto BCDR")
            recommendations.append("Enable SAML/SSO enforcement for Datto BCDR portal")

        return create_response(
            result={criteriaKey: is_saml_enforced},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"samlEnforced": is_saml_enforced}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
