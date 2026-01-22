"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft
Category: Identity / Authentication

Evaluates the MFA status by checking authentication method configurations for enabled methods.
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
                    recommendations=None, input_summary=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "passReasons": pass_reasons or [],
            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "isMFAEnforcedForUsers",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"

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

        # Check for API error response
        if 'error' in data:
            error_info = data.get('error', {})
            inner_error = error_info.get('innerError', {})
            return create_response(
                result={criteriaKey: False},
                validation={"status": "error", "errors": [error_info.get('message', 'API error')], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={
                    "errorCode": error_info.get('code'),
                    "innerErrorCode": inner_error.get('code') if inner_error else None
                }
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Ensure authenticationMethodConfigurations is type list
        value = data.get('authenticationMethodConfigurations', [])
        if not isinstance(value, list):
            if value is None:
                value = []
            else:
                value = [data.get('authenticationMethodConfigurations')]

        # Find enabled authentication methods
        mfa_enrolled = []
        if 'authenticationMethodConfigurations' in data:
            mfa_enrolled = [
                {
                    "id": obj.get('id', ''),
                    "state": obj.get('state', 'enabled'),
                    "includeTargets": obj.get('includeTargets', [])
                }
                for obj in value
                if isinstance(obj, dict) and 'state' in obj and str(obj['state']).lower() == "enabled"
            ]

        is_enforced = len(mfa_enrolled) > 0

        if is_enforced:
            method_ids = [m['id'] for m in mfa_enrolled if m['id']]
            pass_reasons.append(f"MFA is enforced with {len(mfa_enrolled)} enabled authentication method(s)")
            if method_ids:
                pass_reasons.append(f"Enabled methods: {', '.join(method_ids[:5])}")
        else:
            fail_reasons.append("No enabled authentication methods found")
            recommendations.append("Enable MFA authentication methods in Azure AD")

        return create_response(
            result={criteriaKey: is_enforced},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={
                "enabledMethods": len(mfa_enrolled),
                "totalMethods": len(value)
            }
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
