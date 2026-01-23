"""
Transformation: authTypesAllowed
Vendor: Microsoft
Category: Identity / Authentication

Evaluates if only secure authentication types are allowed (FIDO2, Microsoft Authenticator, or properly configured Temporary Access Pass).
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
        enabled_methods = [obj for obj in auth_configs if obj.get('state', '').lower() == "enabled"]

        # Secure methods that are always allowed
        secure_methods = ['fido2', 'microsoftauthenticator', 'softwareoath']

        # Filter to find non-secure auth types
        other_auth_types = [
            auth_type for auth_type in enabled_methods
            if auth_type.get('id', '').lower() not in secure_methods
        ]

        # Check for temporary access pass configuration
        temp_access_obj = next((auth_type for auth_type in enabled_methods if auth_type.get('id', '').lower() == 'temporaryaccesspass'), None)
        has_temporary_access = temp_access_obj is not None
        temp_access_timeout = False
        if temp_access_obj:
            max_lifetime = temp_access_obj.get('maximumLifetimeInMinutes')
            try:
                if max_lifetime is not None and int(max_lifetime) > 0:
                    temp_access_timeout = True
            except (ValueError, TypeError):
                pass

        # Check for presence of FIDO2 or Microsoft Authenticator
        has_fido2 = any(auth_type.get('id', '').lower() == 'fido2' for auth_type in enabled_methods)
        has_ms_auth = any(auth_type.get('id', '').lower() == 'microsoftauthenticator' for auth_type in enabled_methods)

        # Determine if auth types are allowed
        if len(other_auth_types) > 0:
            # Allow if only temp access pass with proper timeout and FIDO2/MS Auth present
            if (len(other_auth_types) == 1 and
                has_temporary_access and
                temp_access_timeout and
                (has_fido2 or has_ms_auth)):
                is_allowed = True
            else:
                is_allowed = False
        else:
            is_allowed = True

        if is_allowed:
            secure_enabled = [m.get('id') for m in enabled_methods if m.get('id', '').lower() in secure_methods]
            pass_reasons.append(f"Only secure authentication methods enabled: {', '.join(secure_enabled)}")
            if has_temporary_access and temp_access_timeout:
                pass_reasons.append("Temporary Access Pass configured with proper lifetime limit")
        else:
            insecure_names = [m.get('id', 'unknown') for m in other_auth_types]
            fail_reasons.append(f"Insecure authentication methods enabled: {', '.join(insecure_names)}")
            recommendations.append("Disable legacy authentication methods and use only FIDO2, Microsoft Authenticator, or properly configured Temporary Access Pass")

        return create_response(
            result={criteriaKey: is_allowed, "authTypes": other_auth_types},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEnabledMethods": len(enabled_methods), "insecureMethods": len(other_auth_types), "hasFido2": has_fido2, "hasMsAuth": has_ms_auth}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "authTypes": []},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
