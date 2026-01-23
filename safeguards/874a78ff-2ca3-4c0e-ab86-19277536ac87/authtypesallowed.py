"""
Transformation: authTypesAllowed
Vendor: Microsoft
Category: Identity / Authentication

Evaluates if only secure authentication types (FIDO2, Microsoft Authenticator) are allowed.
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
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "validationStatus": validation.get("status", "unknown"),
            "validationErrors": validation.get("errors", []),
            "validationWarnings": validation.get("warnings", []),
            "transformationErrors": transformation_errors or [],

            "apiErrors": api_errors or [],
            "passReasons": pass_reasons or [],

            "failReasons": fail_reasons or [],
            "recommendations": recommendations or [],
            "inputSummary": input_summary or {},
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "authTypesAllowed",
                "vendor": "Microsoft",
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

        auth_configs = data.get('authenticationMethodConfigurations', [])

        # Find enabled authentication methods
        enabled_methods = [
            {
                "id": obj.get('id', ''),
                "state": obj.get('state', 'enabled'),
                "includeTargets": obj.get('includeTargets', [])
            }
            for obj in auth_configs
            if obj.get('state', '').lower() == "enabled"
        ]

        # Filter to find non-secure auth types (anything other than FIDO2 or Microsoft Authenticator)
        secure_methods = ['fido2', 'microsoftauthenticator']
        insecure_methods = [
            auth_type for auth_type in enabled_methods
            if auth_type['id'].lower() not in secure_methods
        ]

        # Pass if no insecure methods are enabled
        is_allowed = len(insecure_methods) == 0

        if is_allowed:
            if len(enabled_methods) > 0:
                method_names = [m['id'] for m in enabled_methods[:5]]
                pass_reasons.append(f"Only secure authentication methods enabled: {', '.join(method_names)}")
            else:
                pass_reasons.append("No authentication methods configured")
        else:
            insecure_names = [m['id'] for m in insecure_methods[:5]]
            fail_reasons.append(f"Insecure authentication methods enabled: {', '.join(insecure_names)}")
            recommendations.append("Disable legacy authentication methods and use only FIDO2 or Microsoft Authenticator")

        return create_response(
            result={criteriaKey: is_allowed, "authTypes": insecure_methods},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEnabledMethods": len(enabled_methods), "insecureMethods": len(insecure_methods)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "authTypes": []},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
