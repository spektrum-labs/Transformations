"""
Transformation: confirmPasswordPolicyEnforced
Vendor: Microsoft
Category: Identity / Password Policy

Evaluates if password policy is enforced using Microsoft Graph Conditional Access
policies (identity/conditionalAccess/policies). Password policy is considered
enforced when either an enabled policy blocks legacy authentication (e.g. Exchange
ActiveSync, other legacy clients) or an enabled policy has authentication strength
configured (traditional password / strong authentication requirements).
"""

import json
from datetime import datetime


def transform(input):
    criteriaKey = "confirmPasswordPolicyEnforced"

    # Legacy client app types targeted by "Block legacy authentication" policies
    legacy_client_app_types = ("exchangeActiveSync", "other")

    def get_policies_list(data):
        """Extract list of Conditional Access policies from Graph API response."""
        if data is None:
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("value", [])
        return []

    def is_legacy_auth_blocked(policies):
        """True if any enabled policy blocks legacy authentication."""
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
            if any(t in client_types for t in legacy_client_app_types):
                return True
        return False

    def has_mfa_enforcement(policies):
        """True if any enabled policy requires MFA."""
        if not isinstance(policies, list):
            return False
        for p in policies:
            if isinstance(p, dict) and p.get("state") == "enabled":
                built_in = (p.get("grantControls") or {}).get("builtInControls") or []
                if "mfa" in built_in:
                    return True
        return False

    def has_authentication_strength(policies):
        """True if any enabled policy has authentication strength configured."""
        if not isinstance(policies, list):
            return False
        for p in policies:
            if not isinstance(p, dict) or p.get("state") != "enabled":
                continue
            grant_controls = p.get("grantControls") or {}
            auth_strength = grant_controls.get("authenticationStrength")
            if auth_strength is None or auth_strength == "None":
                continue
            if isinstance(auth_strength, dict) and auth_strength.get("id"):
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
                        recommendations=None, input_summary=None, transformation_errors=None,
                        api_errors=None, additional_findings=None):
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

        policies = get_policies_list(data)
        legacy_auth_blocked = is_legacy_auth_blocked(policies)
        mfa_enforced = has_mfa_enforcement(policies)
        auth_strength_enforced = has_authentication_strength(policies)

        # Password policy is enforced when either legacy auth is blocked or
        # authentication strength is in place (traditional password / strong auth)
        is_enforced = legacy_auth_blocked or auth_strength_enforced

        if is_enforced:
            if legacy_auth_blocked:
                pass_reasons.append(
                    "An enabled Conditional Access policy blocks legacy authentication "
                    "(e.g. Exchange ActiveSync, other legacy clients)"
                )
            if auth_strength_enforced:
                pass_reasons.append(
                    "An enabled Conditional Access policy has authentication strength "
                    "configured (traditional password / strong authentication requirements)"
                )
            if mfa_enforced:
                additional_findings.append("MFA is required by at least one enabled policy")
        else:
            fail_reasons.append(
                "No enabled Conditional Access policy found that blocks legacy authentication "
                "or has authentication strength configured"
            )
            recommendations.append(
                "Create and enable a Conditional Access policy to block legacy authentication "
                "(template: Block legacy authentication) and/or configure authentication strength "
                "in Azure AD / Entra ID"
            )
            if not policies:
                fail_reasons.append("No Conditional Access policies returned in API response")

        input_summary = {
            "policyCount": len(policies),
            "legacyAuthBlocked": legacy_auth_blocked,
            "mfaEnforced": mfa_enforced,
            "authenticationStrengthEnforced": auth_strength_enforced,
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
