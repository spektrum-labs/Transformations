"""
Transformation: isMFAConfiguredForSecurityAdmins
Vendor: Microsoft Entra ID  |  Category: Multifactor Authentication
Evaluates: Whether MFA is required for security admin roles via Conditional Access

A role is covered by a policy that is enabled, requires MFA (via builtInControls
or authenticationStrength), applies to every cloud app or the Microsoft Admin
Portals, is not limited to risky sign-ins, and targets the role ("All" users,
"All" roles, or the role id) without excluding it. The check passes only when
every one of the six security admin roles is covered: a policy for one role
says nothing about the other five.

API: GET /v1.0/identity/conditionalAccess/policies

Named accounts (#101): when the workflow merges the policy list as conditionalAccessPolicies with the role
assignments and the MFA registration report (see below), the first reason and inputSummary name the holders of
these roles the finding is about. The verdict is unchanged.
"""
import json
from datetime import datetime

# Well-known Microsoft Entra security admin role template IDs (built-in roles; the same in every tenant).
# Source: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
# Conditional Access Administrator is b1be1c3e-... and Privileged Authentication Administrator is 7be44c8a-...;
# earlier versions held f28a1f50-... (SharePoint Administrator) and 7698a772-... (Cloud Device Administrator)
# under those names.
SECURITY_ADMIN_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
}


# #101: the finding names the affected accounts when the workflow merges the policy list (conditionalAccessPolicies)
# with two per-account reads:
#   roleAssignments      GET /v1.0/roleManagement/directory/roleAssignments?$expand=principal($select=id)
#                        (RoleManagement.Read.Directory or Directory.Read.All; active assignments only)
#   registrationDetails  GET /v1.0/reports/authenticationMethods/userRegistrationDetails
#                        (AuditLog.Read.All; Entra ID P1 or P2; disabled users are not listed; up to 36 h behind)
# Docs: https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments
#       https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails
# An affected account is an active holder of one of the SECURITY_ADMIN_ROLES ids that is either in a role no
# enabled MFA policy covers, or has no MFA method registered (isMfaRegistered false). The ids are the ones the
# verdict uses, so the names match what the verdict judged. Same shape as #891 / #899: the first reason
# names at most MAX_NAMED, then "and N more"; inputSummary.affectedAccounts carries at most MAX_AFFECTED, with
# the full count in affectedAccountCount. The verdict never reads them, and when the input is the bare policy
# list (today's workflow) the output is exactly what it was.
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
        return admin_accounts(data, SECURITY_ADMIN_ROLES, uncovered)
    except Exception:
        return None


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return {"data": input_data["data"], "validation": input_data["validation"]}
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return {"data": data, "validation": {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}}


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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "isMFAConfiguredForSecurityAdmins", "vendor": "Microsoft Entra ID", "category": "Multifactor Authentication"}
        }
    }


def policy_requires_mfa(policy):
    """Check if a policy requires MFA via builtInControls or authenticationStrength.

    The CA policy response embeds authenticationStrength as {"id": "...", "displayName": "..."}
    without the requirementsSatisfied field (that lives on the full auth strength object at
    /identity/conditionalAccess/authenticationStrength/policies/{id}). All built-in
    authentication strengths (MFA, Passwordless MFA, Phishing-resistant MFA) satisfy MFA,
    so presence with a non-empty id is sufficient.
    """
    grant = policy.get("grantControls", None)
    if not grant or not isinstance(grant, dict):
        return False
    controls = grant.get("builtInControls", [])
    if isinstance(controls, list) and "mfa" in controls:
        return True
    auth_strength = grant.get("authenticationStrength", None)
    if isinstance(auth_strength, dict) and auth_strength.get("id"):
        return True
    return False


# A policy only counts when it applies to every cloud app or to the Microsoft Admin Portals app, as in
# Microsoft's "Require MFA for administrators" policy (Target resources: All resources), and is not limited to
# risky sign-ins: a policy with userRiskLevels or signInRiskLevels set asks for MFA only when Entra ID Protection
# scores the sign-in or user as risky.
ADMIN_APPS = ["All", "MicrosoftAdminPortals"]


def listed(block, name):
    if not isinstance(block, dict):
        return []
    value = block.get(name)
    return value if isinstance(value, list) else []


def policy_covers_admin_roles(policy):
    """The SECURITY_ADMIN_ROLES ids this policy targets, or [] when it does not apply to every admin sign-in."""
    conditions = policy.get("conditions")
    if not isinstance(conditions, dict):
        return []
    apps = listed(conditions.get("applications"), "includeApplications")
    if len([a for a in apps if a in ADMIN_APPS]) == 0:
        return []
    if listed(conditions, "userRiskLevels") or listed(conditions, "signInRiskLevels"):
        return []
    users = conditions.get("users")
    include_users = listed(users, "includeUsers")
    include_roles = listed(users, "includeRoles")
    exclude_roles = listed(users, "excludeRoles")
    covered = []
    for role_id in SECURITY_ADMIN_ROLES:
        if role_id in exclude_roles:
            continue
        if "All" in include_users or "All" in include_roles or role_id in include_roles:
            covered.append(role_id)
    return covered


def not_measured(reason, validation=None):
    return create_response(result={"isMFAConfiguredForSecurityAdmins": None, "matchingPolicies": None,
                                   "coveredRoles": None},
                           validation=validation, fail_reasons=[reason], api_errors=[reason])


def transform(input):
    """True only when every one of the six SECURITY_ADMIN_ROLES is covered by an enabled Conditional Access
    policy that requires MFA (builtInControls "mfa" or an authenticationStrength) for every cloud app or the
    Microsoft Admin Portals, without excluding the role and without being limited to risky sign-ins. All six
    are on Microsoft's minimum list for that policy. False names the roles left uncovered. None, with
    dataCollection.status "error": the policy list was not read, a partial page (@odata.nextLink) leaves a
    role uncovered, or the transformation failed.
    """
    criteriaKey = "isMFAConfiguredForSecurityAdmins"

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        extracted = extract_input(input)
        data = extracted["data"]
        validation = extracted["validation"]

        if validation.get("status") == "failed":
            return not_measured("Input validation failed", validation)

        # Extract policies from the conditional access response. The #101 workflow merges it under
        # conditionalAccessPolicies next to the per-account reads; it is unwrapped exactly as a bare body is.
        accounts_data = None
        if isinstance(data, dict) and "conditionalAccessPolicies" in data:
            accounts_data = data
            data = extract_input(data.get("conditionalAccessPolicies"))["data"]
        partial = False
        if isinstance(data, dict) and isinstance(data.get("value"), list) and not data.get("error"):
            policies = data.get("value")
            partial = bool(data.get("@odata.nextLink"))
        elif isinstance(data, list):
            policies = data
        else:
            return not_measured("The Conditional Access policy list was not read", validation)

        pass_reasons = []
        fail_reasons = []
        recommendations = []
        additional_findings = []

        matching_policies = []
        report_only_policies = []
        covered_ids = []

        for policy in policies:
            if not isinstance(policy, dict):
                continue

            state = str(policy.get("state") or "").lower()
            name = str(policy.get("displayName") or policy.get("id") or "unnamed")

            if not policy_requires_mfa(policy):
                continue

            covered_roles = policy_covers_admin_roles(policy)
            if not covered_roles:
                continue

            if state == "enabled":
                matching_policies.append(name)
                for role_id in covered_roles:
                    if role_id not in covered_ids:
                        covered_ids.append(role_id)
            elif state == "enabledforreportingbutnotenforced":
                report_only_policies.append(name)

        all_covered_roles = [SECURITY_ADMIN_ROLES[r] for r in SECURITY_ADMIN_ROLES if r in covered_ids]
        uncovered = [SECURITY_ADMIN_ROLES[r] for r in SECURITY_ADMIN_ROLES if r not in covered_ids]
        if uncovered and partial:
            return not_measured("Only a partial page of Conditional Access policies was returned and it does not "
                                "cover every security admin role", validation)
        is_configured = not uncovered

        if is_configured:
            pass_reasons.append(
                str(len(matching_policies)) + " enabled Conditional Access policy/policies require MFA for all "
                + str(len(SECURITY_ADMIN_ROLES)) + " security admin roles"
            )
            for pname in matching_policies:
                pass_reasons.append("Policy: " + str(pname))
            pass_reasons.append("Covered roles: " + ", ".join(all_covered_roles))
        else:
            fail_reasons.append(
                str(len(all_covered_roles)) + " of " + str(len(SECURITY_ADMIN_ROLES)) + " security admin roles "
                "require MFA through an enabled Conditional Access policy; not covered: " + ", ".join(uncovered)
            )
            recommendations.append(
                "Enable a Conditional Access policy that requires MFA for all resources and targets every security "
                "admin role (Global, Security, Conditional Access, Privileged Role, Authentication and Privileged "
                "Authentication Administrator)"
            )

        if report_only_policies:
            additional_findings.append(
                "Report-only (not enforced) MFA policies targeting admins: " + ", ".join(report_only_policies)
            )

        input_summary = {
            "totalPolicies": len(policies),
            "enabledMfaAdminPolicies": len(matching_policies),
            "reportOnlyMfaAdminPolicies": len(report_only_policies),
            "coveredRoleCount": len(all_covered_roles),
            "uncoveredRoles": uncovered,
        }
        accounts = None
        if accounts_data is not None:
            accounts = named_accounts(accounts_data, [r for r in SECURITY_ADMIN_ROLES if r not in covered_ids])
        if accounts is not None:
            line = accounts_line(accounts, "active holders of the security admin roles this check targets",
                                 "security admin role holders lack enforced or registered MFA")
            input_summary = with_affected(input_summary, accounts)
            if fail_reasons:
                fail_reasons[0] = fail_reasons[0] + "; " + line
            elif pass_reasons and (not accounts["read"] or accounts["affected"]):
                pass_reasons[0] = pass_reasons[0] + "; " + line

        return create_response(
            result={
                criteriaKey: is_configured,
                "matchingPolicies": len(matching_policies),
                "coveredRoles": all_covered_roles,
            },
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            additional_findings=additional_findings,
            input_summary=input_summary
        )

    except Exception as e:
        return not_measured("Transformation error: " + str(e))
