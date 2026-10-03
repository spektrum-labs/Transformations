"""isCAAuthStrengthPhishingResistantRequired for Microsoft Entra ID (Azure AD and Azure AD One-Click), from
GET /v1.0/identity/conditionalAccess/policies (the method getConditionalAccessPolicies on both definitions).

Permission: Policy.Read.All, which both apps already hold for the Conditional Access reads. Graph returns each
policy's grantControls.authenticationStrength inline, allowedCombinations included, so the authentication strength
policies need no separate read (GET /v1.0/policies/authenticationStrengthPolicies, also Policy.Read.All, is NOT
called). No new permission.

Requirement asked (IAM-001, IAM-002a): "phishing-resistant MFA is REQUIRED at sign-in". The authentication methods
policy only says which methods are allowed; Conditional Access says what sign-in demands.

A policy QUALIFIES when all of these hold:
- state is "enabled" (report-only and disabled policies enforce nothing);
- it covers every cloud app (includeApplications contains "All"; excludeApplications empty) and every sign-in
  (no platform, location, client-app, device-filter, sign-in-risk, user-risk or authentication-flow condition that
  narrows it; clientAppTypes empty or ["all"]; locations absent or including "All" with no exclusion);
- grantControls.authenticationStrength is set and EVERY allowed combination is phishing-resistant:
  fido2, windowsHelloForBusiness or x509CertificateMultiFactor (the built-in "Phishing-resistant MFA" strength);
  deviceBasedPush, passwordless phone sign-in, OTP, SMS, voice, TAP and federated factors are not;
- no other grant control can satisfy the policy instead: operator "AND", or the strength is the only control.

Results:
- isCAAuthStrengthPhishingResistantRequired: True when a qualifying policy targets ALL users (includeUsers "All").
  Up to two excluded user accounts IN TOTAL are allowed (Microsoft and CIS emergency-access guidance) and named in
  the reason ("PASS with N excluded emergency-access accounts: <ids>"). More than two, an excluded group (size
  unknown), ANY excluded role (an admin who also holds it is excluded) or excluded guests/external users leave
  coverage unproven: None, not False.
- isCAAuthStrengthPhishingResistantRequiredForAdmins (separate result): True when qualifying policies, together,
  cover every directory role in Microsoft's "Require phishing-resistant MFA for administrators" template (or a
  qualifying all-users policy exists), with none of those roles excluded. The same exclusion bounds apply (at most
  two excluded user accounts in total, named; no group, role or guest/external exclusion), else None.
- False: the complete policy list was read and no qualifying policy gives that coverage. For the admin result,
  an enabled phishing-resistant strength scoped to groups, named users or some sign-ins (for example PIM elevation
  through an authentication context) makes it None instead: mapping groups to roles needs reads this key does
  not make, so that is not a proven FAIL.
- None (not evaluated, dataCollection.status "error"): not a policy list, an error envelope, an empty list (a
  tenant without Conditional Access usually means no Entra ID P1 licence, or a read that returned nothing), a
  next-page link (a partial list), a policy that is not an object, or an enabled policy whose strength is present
  but has no allowedCombinations list when no qualifying policy was found.
"""

import json
from datetime import datetime


CRITERIA_KEY = "isCAAuthStrengthPhishingResistantRequired"
ADMIN_KEY = "isCAAuthStrengthPhishingResistantRequiredForAdmins"
RESISTANT_COMBINATIONS = ["fido2", "windowshelloforbusiness", "x509certificatemultifactor"]
MAX_EXCLUDED_USERS = 2
# Microsoft Entra "Require phishing-resistant multifactor authentication for administrators" template roles
ADMIN_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
}


def extract_input(value):
    if isinstance(value, (str, bytes)):
        value = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
    if isinstance(value, dict) and "data" in value and "validation" in value:
        return value["data"], value["validation"]
    data = value
    for attempt in range(3):
        if not isinstance(data, dict):
            break
        nested = None
        for key in ("api_response", "response", "result", "apiResponse", "Output"):
            if isinstance(data.get(key), (dict, list)):
                nested = data[key]
                break
        if nested is None:
            break
        data = nested
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation, errors=(), passed=(), failed=(), findings=(), recommendations=(), summary=None):
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": list(errors)},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {
                "passReasons": list(passed),
                "failReasons": list(failed) + list(errors),
                "recommendations": list(recommendations),
                "additionalFindings": list(findings),
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": CRITERIA_KEY,
                "vendor": "Microsoft Entra ID",
                "category": "Identity and Access Management",
            },
        },
    }


def not_evaluated(message, validation=None, summary=None):
    return create_response({CRITERIA_KEY: None, ADMIN_KEY: None},
                           validation or {"status": "failed", "errors": [message], "warnings": []},
                           errors=[message], summary=summary)


def strings(value):
    """A list of lower-cased strings, or None when the value is not a list of strings."""
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        return None
    return [v.lower() for v in value]


def name_of(policy):
    return str(policy.get("displayName") or policy.get("id") or "policy")[:80]


def strength_state(grant):
    """'resistant', 'weak', 'none' or 'unknown' for a policy's grant controls."""
    if not isinstance(grant, dict):
        return "none"
    strength = grant.get("authenticationStrength")
    if not strength:
        return "none"
    if not isinstance(strength, dict):
        return "unknown"
    combos = strings(strength.get("allowedCombinations"))
    if not combos:
        return "unknown"
    others = strings(grant.get("builtInControls"))
    custom = strings(grant.get("customAuthenticationFactors"))
    terms = strings(grant.get("termsOfUse"))
    if others is None or custom is None or terms is None:
        return "unknown"
    alternatives = [c for c in others if c != "mfa"] + custom
    # mfa next to a strength is redundant under AND and an easier alternative under OR
    if str(grant.get("operator") or "OR").upper() == "OR" and (alternatives or "mfa" in others or terms):
        return "weak"
    if all(c in RESISTANT_COMBINATIONS for c in combos):
        return "resistant"
    return "weak"


def narrowing(conditions):
    """Names of the conditions that limit the policy to some sign-ins, or None when the shape is unreadable."""
    found = []
    apps = conditions.get("applications")
    if not isinstance(apps, dict):
        return None
    include_apps = strings(apps.get("includeApplications"))
    exclude_apps = strings(apps.get("excludeApplications"))
    if include_apps is None or exclude_apps is None:
        return None
    if "all" not in include_apps:
        found.append("not all cloud apps")
    if exclude_apps:
        found.append("excluded apps")
    if apps.get("applicationFilter"):
        found.append("application filter")
    client_types = strings(conditions.get("clientAppTypes"))
    if client_types is None:
        return None
    if client_types and client_types != ["all"]:
        found.append("client app types")
    for key, label in (("platforms", "platforms"), ("devices", "device filter"),
                       ("authenticationFlows", "authentication flows"), ("clientApplications", "client applications")):
        if conditions.get(key):
            found.append(label)
    for key, label in (("signInRiskLevels", "sign-in risk"), ("userRiskLevels", "user risk"),
                       ("servicePrincipalRiskLevels", "service principal risk"),
                       ("insiderRiskLevels", "insider risk")):
        if conditions.get(key):
            found.append(label)
    locations = conditions.get("locations")
    if locations:
        if not isinstance(locations, dict):
            return None
        include_loc = strings(locations.get("includeLocations"))
        exclude_loc = strings(locations.get("excludeLocations"))
        if include_loc is None or exclude_loc is None:
            return None
        if "all" not in include_loc or exclude_loc:
            found.append("locations")
    return found


def transform(input):
    try:
        data, validation = extract_input(input)
    except Exception as error:
        return not_evaluated("The Conditional Access policy list could not be parsed: " + str(error)[:120])
    if str(validation.get("status") or "").lower() == "failed":
        return not_evaluated("Input validation failed", validation)
    if isinstance(data, dict):
        if "error" in data:
            return not_evaluated("Microsoft did not return the Conditional Access policies")
        if data.get("@odata.nextLink"):
            return not_evaluated("The Conditional Access policy list carries a next-page link, so it is partial")
        policies = data.get("value")
    else:
        policies = data
    if not isinstance(policies, list):
        return not_evaluated("No Conditional Access policy list (value array) in the response")
    if not policies:
        return not_evaluated("The Conditional Access policy list is empty (no Entra ID P1 licence, or nothing was "
                             "read); it is not evidence either way")
    if any(not isinstance(p, dict) for p in policies):
        return not_evaluated("The Conditional Access policy list holds an entry that is not a policy")

    all_users_policies, admin_policies, findings, unknown, maybe_admin, near_all = [], [], [], [], [], []
    all_users_excluded, admin_excluded = set(), set()
    covered_roles = set()
    for policy in policies:
        if str(policy.get("state") or "").lower() != "enabled":
            continue
        state = strength_state(policy.get("grantControls"))
        if state == "unknown":
            unknown.append(name_of(policy))
            continue
        if state != "resistant":
            continue
        conditions = policy.get("conditions")
        if not isinstance(conditions, dict):
            unknown.append(name_of(policy))
            continue
        narrow = narrowing(conditions)
        if narrow is None:
            unknown.append(name_of(policy))
            continue
        if narrow:
            findings.append(name_of(policy) + " requires a phishing-resistant strength but only for some sign-ins ("
                            + ", ".join(narrow) + ")")
            maybe_admin.append(name_of(policy))
            continue
        users = conditions.get("users")
        if not isinstance(users, dict):
            unknown.append(name_of(policy))
            continue
        include_users = strings(users.get("includeUsers"))
        exclude_users = strings(users.get("excludeUsers"))
        exclude_groups = strings(users.get("excludeGroups"))
        include_roles = strings(users.get("includeRoles"))
        exclude_roles = strings(users.get("excludeRoles"))
        if None in (include_users, exclude_users, exclude_groups, include_roles, exclude_roles):
            unknown.append(name_of(policy))
            continue
        blockers = []
        if len(exclude_users) > MAX_EXCLUDED_USERS:
            blockers.append(str(len(exclude_users)) + " excluded users")
        if exclude_groups:
            blockers.append(str(len(exclude_groups)) + " excluded group(s) of unknown size")
        if users.get("excludeGuestsOrExternalUsers"):
            blockers.append("guests/external users excluded")
        if exclude_roles:
            # any excluded role counts: a member (an admin included) who also holds it is excluded
            blockers.append(str(len(exclude_roles)) + " excluded role(s)")
        if blockers:
            # close to the requirement, but the exclusions make coverage unproven: not a PASS, not a proven FAIL
            findings.append(name_of(policy) + " requires a phishing-resistant strength but " + ", ".join(blockers))
            if "all" in include_users:
                near_all.append(name_of(policy))
            maybe_admin.append(name_of(policy))
            continue
        if "all" in include_users:
            all_users_policies.append(name_of(policy))
            all_users_excluded.update(exclude_users)
        roles = [r for r in include_roles if r in ADMIN_ROLES]
        if roles:
            covered_roles.update(roles)
            admin_policies.append(name_of(policy))
            admin_excluded.update(exclude_users)
        if "all" not in include_users and (users.get("includeGroups") or [u for u in include_users if u != "none"]):
            maybe_admin.append(name_of(policy))

    missing_roles = [ADMIN_ROLES[r] for r in ADMIN_ROLES if r not in covered_roles]
    all_users = bool(all_users_policies)
    if all_users and len(all_users_excluded) > MAX_EXCLUDED_USERS:
        findings.append("The all-users policies exclude " + str(len(all_users_excluded)) + " user accounts in total "
                        "(more than " + str(MAX_EXCLUDED_USERS) + " emergency-access accounts)")
        near_all.extend(all_users_policies)
        maybe_admin.extend(all_users_policies)
        all_users = False
    admin_set = all_users_excluded if all_users else admin_excluded
    admins = all_users or not missing_roles
    if admins and not all_users and len(admin_excluded) > MAX_EXCLUDED_USERS:
        findings.append("The admin-role policies exclude " + str(len(admin_excluded)) + " user accounts in total "
                        "(more than " + str(MAX_EXCLUDED_USERS) + " emergency-access accounts)")
        maybe_admin.extend(admin_policies)
        admins = False
    summary = {"policiesRead": len(policies), "qualifyingAllUsersPolicies": all_users_policies if all_users else [],
               "qualifyingAdminPolicies": admin_policies, "adminRolesNotCovered": [] if all_users else missing_roles,
               "excludedEmergencyAccessAccounts": sorted(e[:40] for e in admin_set) if (all_users or admins) else [],
               "unreadablePolicies": unknown}
    if unknown and not (all_users and admins):
        return not_evaluated("Enabled Conditional Access polic(ies) " + ", ".join(unknown[:5]) + " have a grant or "
                             "condition shape that cannot be read, so the absence of a phishing-resistant "
                             "requirement is not proven", validation, summary)
    users_value = all_users
    if not all_users and near_all:
        users_value = None
    admin_value = admins
    if not admins and maybe_admin:
        # a phishing-resistant strength scoped to groups, named users, some sign-ins (for example PIM elevation
        # through an authentication context) or with unbounded exclusions may cover the admins; it is not proven
        admin_value = None
        findings.append("Admin coverage not evaluated: phishing-resistant strength required by "
                        + ", ".join(maybe_admin[:5]) + " for groups, named users, some sign-ins or with exclusions, "
                        "which cannot be mapped to every admin role from this read")
    if users_value is None and admin_value is None:
        return not_evaluated("A phishing-resistant authentication strength is required with exclusions or scoping "
                             "that leave coverage unproven: " + "; ".join(findings[:3]), validation, summary)
    result = {CRITERIA_KEY: users_value, ADMIN_KEY: admin_value}
    result.update(summary)
    passed, failed = [], []
    ids = summary["excludedEmergencyAccessAccounts"]
    prefix = ("PASS with " + str(len(ids)) + " excluded emergency-access accounts: " + ", ".join(ids) + ". ") if ids else ""
    if all_users:
        passed.append(prefix + "Enabled Conditional Access policy requires a phishing-resistant authentication strength "
                      "for all users and all cloud apps: " + ", ".join(all_users_policies))
    elif users_value is False:
        failed.append("No enabled Conditional Access policy requires a phishing-resistant authentication strength "
                      "(FIDO2, Windows Hello for Business or multi-factor certificate only) for all users and all "
                      "cloud apps")
    if admins and not all_users:
        passed.append(prefix + "Phishing-resistant authentication strength is required for every administrator role: "
                      + ", ".join(admin_policies))
    elif admin_value is False:
        failed.append("Administrator roles without a required phishing-resistant authentication strength: "
                      + ", ".join(missing_roles))
    return create_response(result, validation, passed=passed, failed=failed, findings=findings, summary=summary,
                           recommendations=[] if all_users else [
                               "Create an enabled Conditional Access policy for all users and all cloud apps that "
                               "grants access only with the built-in 'Phishing-resistant MFA' authentication strength"])
