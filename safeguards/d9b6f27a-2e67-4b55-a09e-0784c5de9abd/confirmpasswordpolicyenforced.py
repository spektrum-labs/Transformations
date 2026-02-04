"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Microsoft
Category: Identity / Password Policy

Evaluates if password policy is enforced using Microsoft Graph Conditional Access
policies (identity/conditionalAccess/policies). Password policy is considered
enforced when an enabled policy blocks legacy authentication (e.g. Exchange
ActiveSync, other legacy clients), which prevents password-only sign-in for
those clients.
"""

import json
from datetime import datetime

# Legacy client app types targeted by "Block legacy authentication" policies
LEGACY_CLIENT_APP_TYPES = ("exchangeActiveSync", "other")


def _get_policies_list(data):
    """Extract list of Conditional Access policies from Graph API response."""
    if data is None:
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("value", [])
    return []


def _is_legacy_auth_blocked(policies):
    """
    Return True if any enabled policy blocks legacy authentication.
    Matches policies with state=enabled, grantControls.builtInControls includes
    'block', and conditions.clientAppTypes includes legacy types.
    """
    if not isinstance(policies, list):
        return False
    for p in policies:
        if not isinstance(p, dict):
            continue
        if p.get("state") != "enabled":
            continue
        grant_controls = p.get("grantControls") or {}
        built_in = grant_controls.get("builtInControls") or []
        if "block" not in built_in:
            continue
        conditions = p.get("conditions") or {}
        client_types = conditions.get("clientAppTypes") or []
        if any(t in client_types for t in LEGACY_CLIENT_APP_TYPES):
            return True
    return False


def _has_mfa_enforcement(policies):
    """Return True if any enabled policy requires MFA."""
    if not isinstance(policies, list):
        return False
    for p in policies:
        if isinstance(p, dict) and p.get("state") == "enabled":
            built_in = (p.get("grantControls") or {}).get("builtInControls") or []
            if "mfa" in built_in:
                return True
    return False


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
                "transformationId": "confirmPasswordPolicyEnforced",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def transform(input):
    criteriaKey = "confirmPasswordPolicyEnforced"

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

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        policies = _get_policies_list(data)
        legacy_auth_blocked = _is_legacy_auth_blocked(policies)
        mfa_enforced = _has_mfa_enforcement(policies)

        # Password policy is enforced when an enabled Conditional Access policy
        # blocks legacy authentication (prevents password-only sign-in for legacy clients)
        is_enforced = legacy_auth_blocked

        if is_enforced:
            pass_reasons.append(
                "An enabled Conditional Access policy blocks legacy authentication "
                "(e.g. Exchange ActiveSync, other legacy clients)"
            )
            if mfa_enforced:
                additional_findings.append("MFA is required by at least one enabled policy")
        else:
            fail_reasons.append(
                "No enabled Conditional Access policy found that blocks legacy authentication"
            )
            recommendations.append(
                "Create and enable a Conditional Access policy to block legacy authentication "
                "(template: Block legacy authentication) in Azure AD / Entra ID"
            )
            if not policies:
                fail_reasons.append("No Conditional Access policies returned in API response")

        input_summary = {
            "policyCount": len(policies),
            "legacyAuthBlocked": legacy_auth_blocked,
            "mfaEnforced": mfa_enforced,
            "policyEnforced": is_enforced,
        }

        return create_response(
            result={criteriaKey: is_enforced},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=input_summary,
            additional_findings=additional_findings if additional_findings else None,
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
