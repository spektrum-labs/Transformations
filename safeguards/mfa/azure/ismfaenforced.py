"""
Transformation: isMFAEnforced
Vendor: Microsoft
Category: Identity / MFA

Evaluates if MFA is enforced at the tenant level via authentication methods and conditional access.
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
                "transformationId": "isMFAEnforced",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def transform(input):
    criteriaKey = "isMFAEnforced"
    default_result = {
        criteriaKey: False,
        "mfaMethodsAvailable": False,
        "enabledMethods": [],
        "policiesEnforcingMFAForUsers": [],
    }

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if not isinstance(data, dict):
            return create_response(
                result=default_result,
                validation=validation,
                fail_reasons=["Unexpected input format: expected a JSON object"]
            )

        if validation.get("status") == "failed":
            return create_response(
                result=default_result,
                validation=validation,
                fail_reasons=["Input validation failed"]
            )

        if "error" in data:
            error_info = data.get("error", {})
            inner_error = error_info.get("innerError", {})
            return create_response(
                result=default_result,
                validation={"status": "error", "errors": [error_info.get("message", "API error")], "warnings": []},
                fail_reasons=[f"Microsoft Graph API error: {error_info.get('code', 'unknown')}"],
                input_summary={"errorCode": error_info.get("code"), "innerErrorCode": inner_error.get("code") if inner_error else None}
            )

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # Def description references authenticationMethodsPolicy status == active, but that field
        # does not exist on the merged getEstateMFAStatus payload; mirror the CA-based logic from
        # safeguards/mfa/azure/ismfaenforcedforusers.py instead.
        auth_methods = data.get("authMethodsPolicy") or {}
        method_configs = _as_list(auth_methods.get("authenticationMethodConfigurations") or [])
        mfa_method_types = ["microsoftauthenticator", "fido2", "softwareoath", "temporaryaccesspass"]
        enabled_methods = []
        for method in method_configs:
            if not isinstance(method, dict):
                continue
            method_id = method.get("id", "")
            state = method.get("state", "disabled")
            if state == "enabled" and method_id.lower() in mfa_method_types:
                enabled_methods.append(method_id)

        methods_available = len(enabled_methods) > 0

        ca_data = data.get("conditionalAccessPolicies") or {}
        policies = _as_list(ca_data.get("value") or [])

        policies_enforcing_mfa_for_users = []
        for policy in policies:
            if not isinstance(policy, dict):
                continue
            if policy.get("state") != "enabled":
                continue
            grant_controls = policy.get("grantControls") or {}
            built_in_controls = grant_controls.get("builtInControls") or []
            if "mfa" not in built_in_controls:
                continue

            conditions = policy.get("conditions") or {}
            users = conditions.get("users") or {}
            include_users = users.get("includeUsers") or []
            include_groups = users.get("includeGroups") or []

            targets_all = "All" in include_users or "all" in include_users
            targets_groups = len(include_groups) > 0

            if targets_all or targets_groups:
                policies_enforcing_mfa_for_users.append(policy.get("displayName"))

        mfa_enforced_for_users = len(policies_enforcing_mfa_for_users) > 0
        is_enforced = methods_available and mfa_enforced_for_users

        if methods_available:
            pass_reasons.append(f"MFA methods enabled: {', '.join(enabled_methods)}")
        else:
            fail_reasons.append("No MFA authentication methods enabled at the tenant level")
            recommendations.append(
                "Enable MFA methods (Microsoft Authenticator, FIDO2, or Software OATH) in authentication methods policy"
            )

        if mfa_enforced_for_users:
            pass_reasons.append(
                f"MFA enforced for users via {len(policies_enforcing_mfa_for_users)} policies: "
                f"{', '.join(policies_enforcing_mfa_for_users[:3])}"
            )
        else:
            fail_reasons.append("No enabled conditional access policies requiring MFA for all users")
            recommendations.append(
                "Create a conditional access policy requiring MFA that targets All Users or relevant groups"
            )

        return create_response(
            result={
                criteriaKey: is_enforced,
                "mfaMethodsAvailable": methods_available,
                "enabledMethods": enabled_methods,
                "policiesEnforcingMFAForUsers": policies_enforcing_mfa_for_users,
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"enabledMethods": len(enabled_methods), "mfaUserPolicies": len(policies_enforcing_mfa_for_users)}
        )

    except Exception as e:
        return create_response(
            result=default_result,
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
