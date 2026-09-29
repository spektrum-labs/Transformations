"""
Transformation: isMFAEnforcedForAdmins
Vendor: Microsoft Entra ID  |  Category: Identity and Access Management
Input: the Azure AD workflow isMFAEnforcedForAdmins, which merges two Graph reads:
  conditionalAccessPolicies  GET /v1.0/identity/conditionalAccess/policies                 (Policy.Read.All)
  securityDefaults           GET /v1.0/policies/identitySecurityDefaultsEnforcementPolicy  (Policy.Read.All)
Docs: https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesspolicy
      https://learn.microsoft.com/en-us/graph/api/resources/identitysecuritydefaultsenforcementpolicy
      https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults
      https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference

Question (CMMC MA.L2-3.7.5): is MFA enforced for every administrator sign-in?

Two ways a tenant enforces it, both read here:
  1. Security defaults on (isEnabled == true). Microsoft: security defaults require MFA for the 14 admin
     roles listed in ADMIN_ROLES below, on every sign-in.
  2. Conditional Access. An admin role is covered by a policy that is ENFORCED (state == "enabled";
     report-only never counts), applies to every cloud app (includeApplications "All") or to the Microsoft
     Admin Portals app ("MicrosoftAdminPortals"), requires MFA (builtInControls "mfa" or an
     authenticationStrength object), and targets the role (includeUsers "All", includeRoles "All", or the
     role's template id) without excluding it (excludeRoles).

Output (numbers first): adminRolesCovered, adminRolesTotal (14), adminMfaRoleCoveragePercentage,
securityDefaultsEnabled, enforcingPolicyCount; isMFAEnforcedForAdmins = every one of the 14 roles covered.

Fails closed (None with dataCollection.status "error"): either read missing or erroring, securityDefaults
without a boolean isEnabled, a CA body that is not a policy collection, or a partial CA page
(@odata.nextLink) that does not already cover every role.
"""
import json
from datetime import datetime

KEY = "isMFAEnforcedForAdmins"
WRAPPERS = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse", "data"]

# Built-in role TEMPLATE ids (the same in every tenant), from Microsoft's permissions reference. These are the
# 14 roles security defaults protect, which is also Microsoft's "Require MFA for administrators" CA template.
ADMIN_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
}
ADMIN_APPS = ["All", "MicrosoftAdminPortals"]


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "azure_ismfaenforcedforadmins",
                         "vendor": "Microsoft Entra ID", "category": "Identity and Access Management"},
        },
    }


def not_measured(reason, validation=None):
    return create_response(result={KEY: None, "adminRolesCovered": None, "adminRolesTotal": len(ADMIN_ROLES)},
                           validation=validation, api_errors=[reason], fail_reasons=[reason])


def unwrap(data):
    for attempt in range(6):
        if isinstance(data, (str, bytes)):
            try:
                data = json.loads(data)
            except ValueError:
                return None
        if not isinstance(data, dict) or "conditionalAccessPolicies" in data or "securityDefaults" in data:
            return data
        moved = False
        for key in WRAPPERS:
            if key in data and isinstance(data.get(key), (dict, list)):
                data = data[key]
                moved = True
                break
        if not moved:
            return data
    return data


def listed(block, name):
    if not isinstance(block, dict):
        return []
    value = block.get(name)
    return value if isinstance(value, list) else []


def requires_mfa(policy):
    grant = policy.get("grantControls")
    if not isinstance(grant, dict):
        return False
    if "mfa" in listed(grant, "builtInControls"):
        return True
    strength = grant.get("authenticationStrength")
    return isinstance(strength, dict) and bool(strength.get("id"))


def roles_covered(policy):
    conditions = policy.get("conditions")
    if not isinstance(conditions, dict):
        return []
    apps = listed(conditions.get("applications"), "includeApplications")
    if len([a for a in apps if a in ADMIN_APPS]) == 0:
        return []
    users = conditions.get("users")
    include_users = listed(users, "includeUsers")
    include_roles = listed(users, "includeRoles")
    exclude_roles = listed(users, "excludeRoles")
    covered = []
    for role_id in ADMIN_ROLES:
        if role_id in exclude_roles:
            continue
        if "All" in include_users or "All" in include_roles or role_id in include_roles:
            covered.append(role_id)
    return covered


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input)
        validation = {"status": "unknown", "errors": [], "warnings": []}
        data = input
        if isinstance(input, dict) and "data" in input and "validation" in input:
            data = input.get("data")
            if isinstance(input.get("validation"), dict):
                validation = input.get("validation")
        data = unwrap(data)
        if not isinstance(data, dict):
            return not_measured("Unrecognised input: expected the merged Conditional Access and security defaults reads",
                                validation)
        defaults = data.get("securityDefaults")
        ca = data.get("conditionalAccessPolicies")
        if not isinstance(defaults, dict) or defaults.get("error") or not isinstance(defaults.get("isEnabled"), bool):
            return not_measured("The security defaults policy was not read (isEnabled missing)", validation)
        if not isinstance(ca, dict) or ca.get("error") or not isinstance(ca.get("value"), list):
            return not_measured("The Conditional Access policy list was not read", validation)
        total = len(ADMIN_ROLES)
        defaults_on = defaults.get("isEnabled") is True
        covered = {}
        enforcing = []
        for policy in ca.get("value"):
            if not isinstance(policy, dict) or str(policy.get("state") or "") != "enabled" or not requires_mfa(policy):
                continue
            roles = roles_covered(policy)
            if roles:
                enforcing.append(str(policy.get("displayName") or policy.get("id") or "unnamed"))
                for role_id in roles:
                    covered[role_id] = True
        if defaults_on:
            for role_id in ADMIN_ROLES:
                covered[role_id] = True
        count = len(covered)
        if count < total and bool(ca.get("@odata.nextLink")):
            return not_measured("Only a partial page of Conditional Access policies was returned and it does not cover "
                                "every admin role", validation)
        pct = (count * 100) // total
        result = {
            KEY: count == total,
            "adminRolesCovered": count,
            "adminRolesTotal": total,
            "adminMfaRoleCoveragePercentage": pct,
            "securityDefaultsEnabled": defaults_on,
            "enforcingPolicyCount": len(enforcing),
        }
        summary = {"policyCount": len(ca.get("value")), "securityDefaultsEnabled": defaults_on}
        if count == total:
            why = "Security defaults are on (MFA required for all 14 admin roles)" if defaults_on else \
                "Enforced Conditional Access requires MFA for all 14 admin roles: " + ", ".join(enforcing[:5])
            return create_response(result, validation, pass_reasons=[why], input_summary=summary)
        missing = [ADMIN_ROLES[r] for r in ADMIN_ROLES if r not in covered]
        return create_response(result, validation,
                               fail_reasons=[str(count) + " of " + str(total) + " admin roles require MFA through an "
                                             "enforced policy; not covered: " + ", ".join(missing)],
                               recommendations=["Enforce (not report-only) a Conditional Access policy requiring MFA for "
                                                "all admin roles, or turn on security defaults"],
                               input_summary=summary)
    except Exception as e:
        return not_measured("Transformation error: " + str(e))
