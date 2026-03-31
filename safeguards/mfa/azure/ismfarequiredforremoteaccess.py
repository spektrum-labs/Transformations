"""
Transformation: isMFARequiredForRemoteAccess
Vendor: Microsoft Entra ID  |  Category: Multifactor Authentication
Evaluates: Whether MFA is required for remote access (VPN/VDI)
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
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
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []), "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success", "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [], "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFARequiredForRemoteAccess", "vendor": "Microsoft Entra ID", "category": "Multifactor Authentication"}
        }
    }


def safe_dict(val):
    """Return val if it's a dict, otherwise empty dict.
    Handles the Microsoft Graph pattern of returning string 'None' for null fields."""
    return val if isinstance(val, dict) else {}


def requires_mfa(policy):
    """Check if a policy enforces MFA via any mechanism."""
    grant = safe_dict(policy.get('grantControls'))
    built_in = grant.get('builtInControls', [])
    if not isinstance(built_in, list):
        built_in = []
    custom_factors = grant.get('customAuthenticationFactors', [])
    if not isinstance(custom_factors, list):
        custom_factors = []
    auth_strength = grant.get('authenticationStrength')

    if 'mfa' in built_in:
        return True
    if any('mfa' in f.lower() for f in custom_factors if isinstance(f, str)):
        return True
    if isinstance(auth_strength, dict) and auth_strength.get('id'):
        return True
    return False


def applies_to_remote(policy):
    """Check if a policy applies to non-trusted (remote) locations.
    A policy applies to remote access if:
    - No location condition (applies everywhere)
    - includeLocations contains 'All' or specific locations beyond just AllTrusted
    """
    conditions = safe_dict(policy.get('conditions'))
    locations = conditions.get('locations')
    if not isinstance(locations, dict):
        return True  # No location restriction = applies everywhere including remote
    include = locations.get('includeLocations', [])
    if not isinstance(include, list):
        return True
    exclude = locations.get('excludeLocations', [])
    if not isinstance(exclude, list):
        exclude = []
    # If only trusted locations are included, it does NOT apply to remote
    if include == ['AllTrusted']:
        return False
    return True


def evaluate(data):
    """Core evaluation logic."""
    try:
        if isinstance(data, dict):
            policies = data.get('value', [])
        elif isinstance(data, list):
            policies = data
        else:
            policies = []

        if not isinstance(policies, list):
            policies = []

        remote_mfa_policies = [
            p for p in policies
            if isinstance(p, dict)
            and p.get('state') == 'enabled'
            and requires_mfa(p)
            and applies_to_remote(p)
        ]
        return {
            "isMFARequiredForRemoteAccess": len(remote_mfa_policies) > 0,
            "matchingPolicies": len(remote_mfa_policies),
            "policyNames": [p.get('displayName', 'Unknown') for p in remote_mfa_policies]
        }
    except Exception as e:
        return {"isMFARequiredForRemoteAccess": False, "error": str(e)}


def transform(input):
    criteriaKey = "isMFARequiredForRemoteAccess"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        extra_fields = {k: v for k, v in eval_result.items() if k != criteriaKey and k != "error"}

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            pass_reasons.append(f"{criteriaKey} check passed")
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
        else:
            fail_reasons.append(f"{criteriaKey} check failed")
            if "error" in eval_result:
                fail_reasons.append(eval_result["error"])
            recommendations.append(f"Review Microsoft Entra ID configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={criteriaKey: result_value, **extra_fields}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
