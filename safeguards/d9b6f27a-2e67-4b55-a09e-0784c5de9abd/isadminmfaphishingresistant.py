"""
Transformation: isAdminMFAPhishingResistant
Vendor: Microsoft
Category: Identity / Authentication

Evaluates if admin MFA is phishing resistant (only FIDO2 or Microsoft Authenticator enabled).
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
                "transformationId": "isAdminMFAPhishingResistant",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isAdminMFAPhishingResistant"

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

        # Phishing resistant methods
        phishing_resistant = ['fido2', 'microsoftauthenticator']

        # Filter to find non-phishing-resistant auth types
        other_auth_types = [
            auth_type for auth_type in enabled_methods
            if auth_type['id'].lower() not in phishing_resistant
        ]

        # Pass if no non-phishing-resistant methods are enabled
        is_resistant = len(other_auth_types) == 0

        if is_resistant:
            if len(enabled_methods) > 0:
                method_names = [m['id'] for m in enabled_methods]
                pass_reasons.append(f"Only phishing-resistant authentication methods enabled: {', '.join(method_names)}")
            else:
                pass_reasons.append("No authentication methods configured")
        else:
            insecure_names = [m['id'] for m in other_auth_types]
            fail_reasons.append(f"Non-phishing-resistant authentication methods enabled: {', '.join(insecure_names)}")
            recommendations.append("Disable non-phishing-resistant authentication methods for admins and use only FIDO2 or Microsoft Authenticator")

        return create_response(
            result={criteriaKey: is_resistant, "authTypes": other_auth_types},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"totalEnabledMethods": len(enabled_methods), "nonResistantMethods": len(other_auth_types)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "authTypes": []},
            validation={"status": "error", "errors": [str(e)], "warnings": []},
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
