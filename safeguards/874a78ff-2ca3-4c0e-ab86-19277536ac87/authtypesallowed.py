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
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }



def parse_api_error(raw_error: str, source: str = None) -> tuple:
    """Parse raw API error into clean message with source."""
    raw_lower = raw_error.lower() if raw_error else ''
    src = source or "external service"

    if '401' in raw_error:
        return (f"Could not connect to {src}: Authentication failed (HTTP 401)",
                f"Verify {src} credentials and permissions are valid")
    elif '403' in raw_error:
        return (f"Could not connect to {src}: Access denied (HTTP 403)",
                f"Verify the integration has required {src} permissions")
    elif '404' in raw_error:
        return (f"Could not connect to {src}: Resource not found (HTTP 404)",
                f"Verify the {src} resource and configuration exist")
    elif '429' in raw_error:
        return (f"Could not connect to {src}: Rate limited (HTTP 429)",
                "Retry the request after waiting")
    elif '500' in raw_error or '502' in raw_error or '503' in raw_error:
        return (f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
                f"{src} may be temporarily unavailable, retry later")
    elif 'timeout' in raw_lower:
        return (f"Could not connect to {src}: Request timed out",
                "Check network connectivity and retry")
    elif 'connection' in raw_lower:
        return (f"Could not connect to {src}: Connection failed",
                "Check network connectivity and firewall settings")
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (f"Could not connect to {src}: {clean}",
                f"Check {src} credentials and configuration")

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


        # Check for API error (e.g., OAuth failure)
        if isinstance(data, dict) and 'PSError' in data:
            api_error, recommendation = parse_api_error(data.get('PSError', ''), source="Microsoft 365")
            return create_response(
                result={criteriaKey: False},
                validation={"status": "skipped", "errors": [], "warnings": ["API returned error"]},
                api_errors=[api_error],
                fail_reasons=["Could not retrieve data from Microsoft 365"],
                recommendations=[recommendation]
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
