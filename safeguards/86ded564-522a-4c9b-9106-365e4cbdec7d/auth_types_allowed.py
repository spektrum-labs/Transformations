"""
Transformation: authTypesAllowed
Vendor: Generic IDP
Category: Identity / Authentication

Returns a list of Authenticator Types that are active and evaluates if only FIDO/OTP types are allowed.
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

        # Handle list input
        if isinstance(data, list):
            items = data
        else:
            items = []

        authTypes = []
        for item in items:
            if isinstance(item, dict) and item.get('status', '').lower() == 'active':
                factor_type = item.get('factorType', '')
                if factor_type.lower() != 'sms':
                    if factor_type.lower() == 'token:software:totp':
                        authTypes.append('OTP')
                    else:
                        authTypes.append(factor_type)

        # Filter to keep only auth types that are NOT FIDO or OTP
        otherAuthTypes = [auth_type for auth_type in authTypes if auth_type.lower() not in ['fido', 'otp']]

        # Pass if only FIDO/OTP types are allowed (no other types)
        is_allowed = len(otherAuthTypes) == 0

        if is_allowed:
            if authTypes:
                pass_reasons.append(f"Only secure authentication types are allowed: {', '.join(authTypes)}")
            else:
                pass_reasons.append("No insecure authentication types found")
        else:
            fail_reasons.append(f"Non-FIDO/OTP authentication types found: {', '.join(otherAuthTypes)}")
            recommendations.append("Restrict authentication to FIDO and OTP methods only")

        return create_response(
            result={criteriaKey: is_allowed, "authTypes": authTypes},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "totalAuthTypes": len(authTypes),
                "secureAuthTypes": len([a for a in authTypes if a.lower() in ['fido', 'otp']]),
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
