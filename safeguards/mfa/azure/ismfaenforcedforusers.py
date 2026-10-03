"""
Transformation: isMFAEnforcedForUsers
Vendor: Microsoft Azure AD
Category: Identity / MFA

Evaluates if MFA is enforced for all users by checking that MFA methods are enabled
at the tenant level and conditional access policies require MFA for all users.

Input (merged workflow): {"authMethodsPolicy": GET /v1.0/policies/authenticationMethodsPolicy,
"conditionalAccessPolicies": GET /v1.0/identity/conditionalAccess/policies}.

Not evaluated (value None, dataCollection.status "error"):
- no Microsoft MFA method is enabled but an external authentication method (for example Cisco
  Duo, @odata.type externalAuthenticationMethodConfiguration) is: the factor is enforced by that
  provider, which Entra cannot grade (J.J., 3 Oct 2026; same rule as authtypesallowed.py and
  entra_strongauth_methods.py). It is never a FAIL. Seen at passport 7c1375c8, where a tenant
  that requires Duo through Conditional Access read "No MFA authentication methods enabled";
- the authentication methods policy or the Conditional Access policies were not read (error
  envelope, no authenticationMethodConfigurations array, no policy list), or input validation
  failed: a read that failed is not evidence either way.

FAIL stays only when both were read and they show no MFA: no Microsoft MFA method and no
external method enabled, or no enabled Conditional Access policy requiring MFA for users.
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
                "transformationId": "isMFAEnforcedForUsers",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def is_external_method(method):
    """An Entra external authentication method (EAM), for example Cisco Duo."""
    return "externalauthenticationmethodconfiguration" in str(method.get('@odata.type') or '').lower()


def not_evaluated(criteriaKey, reason, validation, input_summary=None, extra=None, findings=None):
    result = {criteriaKey: None}
    if extra:
        result.update(extra)
    return create_response(
        result=result,
        validation=validation,
        input_summary=input_summary,
        additional_findings=findings,
        api_errors=[reason]
    )


def transform(input):
    criteriaKey = "isMFAEnforcedForUsers"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            return not_evaluated(criteriaKey, "Input validation failed: the MFA evidence was not read", validation)

        if not isinstance(data, dict) or not data:
            return not_evaluated(
                criteriaKey,
                "Microsoft Graph returned no MFA evidence (authentication methods policy and Conditional Access policies)",
                validation)

        if 'error' in data:
            error_info = data.get('error')
            code = error_info.get('code', 'unknown') if isinstance(error_info, dict) else 'unknown'
            return not_evaluated(criteriaKey, f"Microsoft Graph API error: {str(code)[:80]}", validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        # 1. Check authentication methods policy — are MFA methods enabled at the tenant level?
        # Graph returns a configuration object for every method it knows, enabled or not, so a
        # missing or empty array means the policy was not read (not that no method is enabled).
        auth_methods = data.get('authMethodsPolicy')
        method_configs = auth_methods.get('authenticationMethodConfigurations') if isinstance(auth_methods, dict) else None
        if not isinstance(method_configs, list) or not method_configs:
            return not_evaluated(
                criteriaKey,
                "The authentication methods policy was not read (no authenticationMethodConfigurations array), "
                "so the absence of an MFA method is not evidence that none is enabled",
                validation)

        ca_data = data.get('conditionalAccessPolicies')
        if isinstance(ca_data, list):
            policies = ca_data
        elif isinstance(ca_data, dict) and 'error' not in ca_data:
            policies = ca_data.get('value')
        else:
            policies = None
        if not isinstance(policies, list):
            return not_evaluated(
                criteriaKey,
                "The Conditional Access policies were not read (no policy list), so the absence of a policy "
                "requiring MFA is not evidence that none exists",
                validation)

        mfa_method_types = ['microsoftauthenticator', 'fido2', 'softwareoath', 'temporaryaccesspass']
        enabled_methods = []
        external_methods = []
        for method in method_configs:
            if not isinstance(method, dict):
                continue
            if str(method.get('state') or 'disabled').lower() != 'enabled':
                continue
            if is_external_method(method):
                external_methods.append(str(method.get('displayName') or method.get('id') or 'external method')[:60])
            elif str(method.get('id') or '').lower() in mfa_method_types:
                enabled_methods.append(str(method.get('id')))

        methods_available = len(enabled_methods) > 0

        # 2. Check conditional access policies — is MFA enforced for all users?
        policies_enforcing_mfa_all_users = []

        for policy in policies:
            if not isinstance(policy, dict) or policy.get('state') != 'enabled':
                continue
            grant_controls = policy.get('grantControls') or {}
            built_in_controls = grant_controls.get('builtInControls') or []
            if 'mfa' not in built_in_controls:
                continue

            conditions = policy.get('conditions') or {}
            users = conditions.get('users') or {}
            include_users = users.get('includeUsers') or []
            include_groups = users.get('includeGroups') or []

            targets_all = 'All' in include_users or 'all' in include_users
            targets_groups = len(include_groups) > 0

            if targets_all or targets_groups:
                policies_enforcing_mfa_all_users.append(policy.get('displayName'))

        mfa_enforced_for_users = len(policies_enforcing_mfa_all_users) > 0
        input_summary = {
            "enabledMethods": len(enabled_methods),
            "externalMethods": external_methods,
            "mfaUserPolicies": len(policies_enforcing_mfa_all_users)
        }
        details = {
            "mfaMethodsAvailable": methods_available,
            "enabledMethods": enabled_methods,
            "externalMethods": external_methods,
            "policiesEnforcingMFAForUsers": policies_enforcing_mfa_all_users
        }

        # 3. An external authentication method (for example Cisco Duo) enforces its own factors,
        # which Entra cannot see. When it stands in for every Microsoft MFA method, the check is
        # not evaluated; it is never a FAIL (J.J., 3 Oct 2026).
        if not methods_available and external_methods:
            findings = []
            if mfa_enforced_for_users:
                findings.append("Conditional Access policies requiring MFA for users: "
                                + ", ".join(str(p)[:80] for p in policies_enforcing_mfa_all_users[:3]))
            return not_evaluated(
                criteriaKey,
                "MFA is provided by an external authentication method (e.g. Duo); Entra cannot grade it. "
                "Enabled external method(s): " + ", ".join(external_methods)
                + "; no Microsoft MFA method is enabled in the authentication methods policy",
                validation, input_summary=input_summary, extra=details, findings=findings)

        is_enforced = methods_available and mfa_enforced_for_users

        if methods_available:
            pass_reasons.append(f"MFA methods enabled: {', '.join(enabled_methods)}")
        else:
            fail_reasons.append("No MFA authentication methods enabled at the tenant level")
            recommendations.append("Enable MFA methods (Microsoft Authenticator, FIDO2, or Software OATH) in authentication methods policy")

        if mfa_enforced_for_users:
            pass_reasons.append(f"MFA enforced for users via {len(policies_enforcing_mfa_all_users)} policies: {', '.join(str(p) for p in policies_enforcing_mfa_all_users[:3])}")
        else:
            fail_reasons.append("No enabled conditional access policies requiring MFA for all users")
            recommendations.append("Create a conditional access policy requiring MFA that targets All Users or relevant groups")

        result = {criteriaKey: is_enforced}
        result.update(details)
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: None},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            api_errors=[f"Transformation error: {str(e)}"]
        )
