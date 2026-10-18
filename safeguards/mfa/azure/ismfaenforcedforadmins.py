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

Named accounts (#101): when the workflow also merges roleAssignments and registrationDetails (see below), the
first reason and inputSummary name the admin role holders the finding is about. The verdict is unchanged.

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

# #101: the finding names the affected accounts when the workflow also carries two per-account reads:
#   roleAssignments      GET /v1.0/roleManagement/directory/roleAssignments?$expand=principal($select=id)
#                        (RoleManagement.Read.Directory or Directory.Read.All; active assignments only)
#   registrationDetails  GET /v1.0/reports/authenticationMethods/userRegistrationDetails
#                        (AuditLog.Read.All; Entra ID P1 or P2; disabled users are not listed; up to 36 h behind)
# Docs: https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments
#       https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails
# An affected account is an active holder of one of the 14 roles that is either in a role no enforced policy
# covers, or has no MFA method registered (isMfaRegistered false). Same shape as #891 / #899: the first reason
# names at most MAX_NAMED, then "and N more"; inputSummary.affectedAccounts carries at most MAX_AFFECTED, with
# the full count in affectedAccountCount. The verdict never reads them, and when the two reads are absent
# (today's workflow) the output is exactly what it was.
MAX_NAMED = 20
MAX_AFFECTED = 50
BODY_WRAPPERS = ["apiResponse", "rawResponse", "response", "result", "data"]


def collection(block):
    """(rows, partial) for a Graph collection read, or (None, False) when it was not read."""
    for attempt in range(4):
        if not isinstance(block, dict) or isinstance(block.get("value"), list):
            break
        moved = False
        for key in BODY_WRAPPERS:
            if isinstance(block.get(key), (dict, list)):
                block = block[key]
                moved = True
                break
        if not moved:
            break
    if isinstance(block, list):
        return block, False
    if isinstance(block, dict) and isinstance(block.get("value"), list) and not block.get("error"):
        return block.get("value"), bool(block.get("@odata.nextLink"))
    return None, False


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def admin_accounts(data, role_ids, uncovered):
    """None when the per-account reads are not in the input; otherwise who is affected and why."""
    if not isinstance(data, dict) or "roleAssignments" not in data:
        return None
    rows, rows_partial = collection(data.get("roleAssignments"))
    if rows is None:
        return {"read": False}
    reg_rows, reg_partial = collection(data.get("registrationDetails"))
    registration = {}
    for reg in reg_rows or []:
        if isinstance(reg, dict) and reg.get("id"):
            registration[str(reg.get("id")).strip().lower()] = reg
    holders = {}
    order = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        role = str(row.get("roleDefinitionId") or "").strip().lower()
        pid = str(row.get("principalId") or "").strip().lower()
        if role not in role_ids or not pid:
            continue
        principal = row.get("principal") if isinstance(row.get("principal"), dict) else {}
        kind = str(principal.get("@odata.type") or "").lower()
        if "serviceprincipal" in kind:
            continue
        if pid not in holders:
            holders[pid] = {"uncovered": False, "group": "group" in kind}
            order.append(pid)
        if role in uncovered:
            holders[pid]["uncovered"] = True
    both = []
    uncovered_only = []
    unregistered_only = []
    not_in_report = 0
    for pid in order:
        holder = holders[pid]
        reg = registration.get(pid)
        registered = None
        if holder["group"]:
            name = "group:" + pid[:64]
        elif reg is None:
            name = pid[:64]
            if reg_rows is not None:
                not_in_report = not_in_report + 1
        else:
            name = str(reg.get("userPrincipalName") or reg.get("userDisplayName") or pid)[:100]
            registered = reg.get("isMfaRegistered")
        unregistered = registered is False
        if holder["uncovered"] and unregistered:
            both.append(name)
        elif holder["uncovered"]:
            uncovered_only.append(name)
        elif unregistered:
            unregistered_only.append(name)
    return {"read": True, "total": len(order), "affected": both + uncovered_only + unregistered_only,
            "uncovered": len(both) + len(uncovered_only), "unregistered": len(both) + len(unregistered_only),
            "registrationRead": reg_rows is not None, "notInReport": not_in_report,
            "partial": rows_partial, "registrationPartial": reg_partial}


def accounts_line(accounts, scope, what):
    """One line naming the tool and its scope, or None when there is nothing to say."""
    if not accounts["read"]:
        return "Microsoft Entra ID (" + scope + "): accounts not named, the directory role assignments were not read"
    line = ("Microsoft Entra ID (" + scope + "): " + str(len(accounts["affected"])) + " of " + str(accounts["total"])
            + " " + what + " (" + str(accounts["uncovered"]) + " in a role no enforced policy covers, "
            + str(accounts["unregistered"]) + " with no MFA method registered)")
    if accounts["affected"]:
        line = line + ": " + name_list(accounts["affected"])
    notes = []
    if accounts["partial"]:
        notes.append("the role assignment list is partial (unread pages), so more holders may exist")
    if not accounts["registrationRead"]:
        notes.append("MFA registration not read (the report needs Entra ID P1 or P2), so only role coverage is judged")
    elif accounts["registrationPartial"]:
        notes.append("the registration report is partial (unread pages)")
    if accounts["notInReport"]:
        notes.append(str(accounts["notInReport"]) + " role holder(s) are not in the registration report (disabled, "
                     "deleted, or up to 36 h report lag), named by object id")
    if notes:
        line = line + "; " + "; ".join(notes)
    return line


def with_affected(summary, accounts):
    if accounts is not None and accounts["read"]:
        summary["affectedAccounts"] = accounts["affected"][:MAX_AFFECTED]
        summary["affectedAccountCount"] = len(accounts["affected"])
    return summary


def named_accounts(data, uncovered):
    """Never lets the naming change the verdict: any surprise here names no one."""
    try:
        return admin_accounts(data, ADMIN_ROLES, uncovered)
    except Exception:
        return None


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
        accounts = named_accounts(data, [r for r in ADMIN_ROLES if r not in covered])
        line = None
        if accounts is not None:
            line = accounts_line(accounts, "active holders of the 14 admin roles", "admin role holders lack enforced "
                                 "or registered MFA")
            summary = with_affected(summary, accounts)
        if count == total:
            why = "Security defaults are on (MFA required for all 14 admin roles)" if defaults_on else \
                "Enforced Conditional Access requires MFA for all 14 admin roles: " + ", ".join(enforcing[:5])
            if line is not None and (not accounts["read"] or accounts["affected"]):
                why = why + "; " + line
            return create_response(result, validation, pass_reasons=[why], input_summary=summary)
        missing = [ADMIN_ROLES[r] for r in ADMIN_ROLES if r not in covered]
        why = (str(count) + " of " + str(total) + " admin roles require MFA through an enforced policy; not covered: "
               + ", ".join(missing))
        if line is not None:
            why = why + "; " + line
        return create_response(result, validation,
                               fail_reasons=[why],
                               recommendations=["Enforce (not report-only) a Conditional Access policy requiring MFA for "
                                                "all admin roles, or turn on security defaults"],
                               input_summary=summary)
    except Exception as e:
        return not_measured("Transformation error: " + str(e))
