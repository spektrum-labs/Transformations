"""
Transformation: isMFAEnabled
Vendor: Microsoft Azure AD
Category: Identity / MFA

Evaluates if MFA is enabled for the environment via conditional access policies.
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
                "transformationId": "isMFAEnabled",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "isMFAEnabled"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return create_response(
                result={criteriaKey: False, "policiesTotal": 0, "policiesWithMFA": 0, "policiesWithoutMFA": 0},
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # 1. Check authentication methods policy — are MFA methods enabled at the tenant level?
        auth_methods = data.get('authMethodsPolicy', {})
        method_configs = auth_methods.get('authenticationMethodConfigurations', [])
        mfa_method_types = ['microsoftauthenticator', 'fido2', 'softwareoath', 'temporaryaccesspass']
        enabled_methods = []
        for method in method_configs:
            method_id = method.get('id', '')
            state = method.get('state', 'disabled')
            if state == 'enabled' and method_id.lower() in mfa_method_types:
                enabled_methods.append(method_id)

        methods_available = len(enabled_methods) > 0

        # 2. Check conditional access policies — is MFA actually enforced?
        ca_data = data.get('conditionalAccessPolicies', {})
        policies = ca_data.get('value', [])
        policies_with_mfa = []
        policies_without_mfa = []

        for policy in policies:
            if policy.get('state') != 'enabled':
                continue
            grant_controls = policy.get('grantControls') or {}
            built_in_controls = grant_controls.get('builtInControls', [])
            if 'mfa' in built_in_controls:
                policies_with_mfa.append(policy.get('displayName'))
            else:
                policies_without_mfa.append(policy.get('displayName'))

        mfa_enforced = len(policies_with_mfa) > 0
        is_enabled = methods_available and mfa_enforced

        if methods_available:
            pass_reasons.append(f"MFA methods enabled: {', '.join(enabled_methods)}")
        else:
            fail_reasons.append("No MFA authentication methods enabled at the tenant level")
            recommendations.append("Enable MFA methods (Microsoft Authenticator, FIDO2, or Software OATH) in authentication methods policy")

        if mfa_enforced:
            pass_reasons.append(f"MFA enforced via {len(policies_with_mfa)} conditional access policies: {', '.join(policies_with_mfa[:3])}")
        else:
            fail_reasons.append("No enabled conditional access policies requiring MFA")
            recommendations.append("Create conditional access policies requiring MFA for users")

        return create_response(
            result={
                criteriaKey: is_enabled,
                "mfaMethodsAvailable": methods_available,
                "enabledMethods": enabled_methods,
                "policiesTotal": len(policies),
                "policiesWithMFA": len(policies_with_mfa),
                "conditionalAccessPoliciesWithMFA": policies_with_mfa
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"enabledMethods": len(enabled_methods), "mfaPolicies": len(policies_with_mfa)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False, "policiesTotal": 0, "policiesWithMFA": 0, "policiesWithoutMFA": 0},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
