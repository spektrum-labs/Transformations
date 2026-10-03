"""
Transformation: isAdminMFAPhishingResistant
Vendor: Microsoft (Azure AD, d9b6f27a)
Category: Identity

Requirement asked: "Only phishing-resistant MFA for admins": admins are REQUIRED to sign in with a
phishing-resistant method. Three Graph bodies are understood; each answers only what it can prove.

1. GET /v1.0/identity/conditionalAccess/policies (getConditionalAccessPolicies; Policy.Read.All, already granted).
   The only body that can prove the requirement. True when enabled Conditional Access policies, for all cloud apps
   and every sign-in, together require an authentication strength made only of phishing-resistant combinations
   (fido2, windowsHelloForBusiness, x509CertificateMultiFactor) for every role in Microsoft's "Require
   phishing-resistant MFA for administrators" template (or for all users), with none of those roles excluded.
   An admin who cannot satisfy that strength is blocked, not phished, so the methods policy is not needed for the
   pass. Otherwise None: CA alone cannot show that admins use a phishable method. Never False.

2. GET /v1.0/policies/authenticationMethodsPolicy (getAuthenticationMethodsPolicy). It shows which methods are
   allowed, never that admins must use one, so it NEVER returns True. Windows Hello for Business is not in this
   policy, so "no FIDO2 / certificate enabled" is never a FAIL either.
   - Email OTP enabled (any target, guests included) -> False. J.J., 3 Oct 2026 00:55 ET: guest-only email OTP
     FAILS (same rule as #833 and #848).
   - Everything else, including nothing enabled, preMigration / migrationInProgress / unknown migration state,
     external methods, partial, truncated or paged bodies -> None.

3. GET /v1.0/security/secureScores?$top=1 (getRecentSecureScores, the current wiring), control AdminMFAV2, which
   measures admin MFA of ANY kind. Until 3 Oct 2026 a 100% score read True, which called push and SMS
   "phishing-resistant" (AT-2 follow-up 3). Now: below 100% -> False (some admins have no MFA at all); 100% ->
   None; no score, no control, ambiguous, PSError, Graph error -> None. Never True.
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
                "transformationId": "isAdminMFAPhishingResistant",
                "vendor": "Microsoft",
                "category": "Identity"
            }
        }
    }


def parse_api_error(raw_error, source=None):
    raw_error = raw_error or ""
    raw_lower = raw_error.lower()
    src = source or "external service"

    if "401" in raw_error:
        return (
            f"Could not connect to {src}: Authentication failed (HTTP 401)",
            f"Verify {src} credentials and permissions are valid",
        )
    elif "403" in raw_error:
        return (
            f"Could not connect to {src}: Access denied (HTTP 403)",
            f"Verify the integration has required {src} permissions",
        )
    elif "404" in raw_error:
        return (
            f"Could not connect to {src}: Resource not found (HTTP 404)",
            f"Verify the {src} resource and configuration exist",
        )
    elif "429" in raw_error:
        return (
            f"Could not connect to {src}: Rate limited (HTTP 429)",
            "Retry the request after waiting",
        )
    elif "500" in raw_error or "502" in raw_error or "503" in raw_error:
        return (
            f"Could not connect to {src}: Service unavailable (HTTP 5xx)",
            f"{src} may be temporarily unavailable, retry later",
        )
    elif "timeout" in raw_lower:
        return (
            f"Could not connect to {src}: Request timed out",
            "Check network connectivity and retry",
        )
    elif "connection" in raw_lower:
        return (
            f"Could not connect to {src}: Connection failed",
            "Check network connectivity and firewall settings",
        )
    else:
        clean = raw_error[:80] + "..." if len(raw_error) > 80 else raw_error
        return (
            f"Could not connect to {src}: {clean}",
            f"Check {src} credentials and configuration",
        )


def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def as_number(value, default=0):
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        try:
            number = float(value)
            return int(number) if number.is_integer() else number
        except ValueError:
            return default
    return default


# Graph v1.0 returns a configuration for every built-in method, enabled or not. A body missing any of these is a
# truncated or partial read, and "nothing phishable enabled" is not evidence from it.
ALWAYS_RETURNED = ["fido2", "microsoftauthenticator", "sms", "temporaryaccesspass", "softwareoath", "voice", "email",
                   "x509certificate"]
STATES = ("enabled", "disabled")
CRITERIA_KEY = "isAdminMFAPhishingResistant"
CONTROL_NAME = "AdminMFAV2"


def unevaluated(message, validation=None, summary=None, findings=None, extra=None):
    result = {CRITERIA_KEY: None}
    if extra:
        result.update(extra)
    return create_response(
        result=result,
        validation=validation or {"status": "error", "errors": [message], "warnings": []},
        api_errors=[message],
        fail_reasons=[message],
        input_summary=summary or {},
        additional_findings=findings or [],
    )


def method_id(config):
    return str(config.get("id") or "").lower()


def from_methods_policy(data, validation):
    if data.get("@odata.nextLink") or data.get("authenticationMethodConfigurations@odata.nextLink"):
        return unevaluated("The authentication methods policy carries a next-page link, so the method list is partial",
                           validation)
    configs = data.get("authenticationMethodConfigurations")
    if not isinstance(configs, list) or not configs:
        return unevaluated("No authenticationMethodConfigurations array: the authentication methods policy was not read",
                           validation)
    for config in configs:
        if (not isinstance(config, dict) or not method_id(config)
                or str(config.get("state") or "").lower() not in STATES):
            return unevaluated("The authentication methods policy is incomplete: a method configuration has no id or "
                               "no enabled/disabled state", validation)
    ids = [method_id(c) for c in configs]
    missing = [m for m in ALWAYS_RETURNED if m not in ids]
    if missing or len(set(ids)) != len(ids):
        return unevaluated("The authentication methods policy looks partial: "
                           + ("it has no configuration for " + ", ".join(missing) if missing
                              else "a method id appears more than once")
                           + "; Graph returns every built-in method, so this is not a complete read", validation)
    enabled = [c for c in configs if str(c.get("state")).lower() == "enabled"]
    email = [c for c in enabled if method_id(c) == "email"]
    migration = str(data.get("policyMigrationState") or "")[:40]
    summary = {"source": "authenticationMethodsPolicy", "enabledMethods": [str(c.get("id"))[:60] for c in enabled],
               "policyMigrationState": migration}
    if email:
        targets = email[0].get("includeTargets")
        guests_only = isinstance(targets, list) and not targets
        return create_response(
            result={CRITERIA_KEY: False, "emailOtpEnabled": True, "emailOtpGuestsOnly": guests_only},
            validation=validation, input_summary=summary,
            fail_reasons=["Email one-time passcode is enabled" + (" for external (guest) users" if guests_only else "")
                          + "; an email-based factor allowed in the tenant, guests included, is not phishing-resistant "
                          "(J.J., 3 Oct 2026)"],
            recommendations=["Disable email OTP in the authentication methods policy and require the built-in "
                             "'Phishing-resistant MFA' authentication strength for admin roles in Conditional Access"])
    return unevaluated("The authentication methods policy shows which methods are allowed, not that admins must use a "
                       "phishing-resistant one (Windows Hello for Business is not listed in it either); a Conditional "
                       "Access authentication strength for admin roles (getConditionalAccessPolicies) is the proof",
                       validation, summary)


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




def from_ca_policies(policies, validation):
    if not policies:
        return unevaluated("The Conditional Access policy list is empty; it is not evidence either way", validation)
    covered, used, unknown, findings = set(), [], [], []
    all_users = False
    for policy in policies:
        if not isinstance(policy, dict):
            return unevaluated("The Conditional Access policy list holds an entry that is not a policy", validation)
        if str(policy.get("state") or "").lower() != "enabled":
            continue
        state = strength_state(policy.get("grantControls"))
        if state == "unknown":
            unknown.append(name_of(policy))
            continue
        if state != "resistant":
            continue
        conditions = policy.get("conditions")
        narrow = narrowing(conditions) if isinstance(conditions, dict) else None
        users = conditions.get("users") if isinstance(conditions, dict) else None
        if narrow is None or not isinstance(users, dict):
            unknown.append(name_of(policy))
            continue
        if narrow:
            findings.append(name_of(policy) + " applies to some sign-ins only (" + ", ".join(narrow) + ")")
            continue
        include_users = strings(users.get("includeUsers"))
        exclude_users = strings(users.get("excludeUsers"))
        exclude_groups = strings(users.get("excludeGroups"))
        include_roles = strings(users.get("includeRoles"))
        exclude_roles = strings(users.get("excludeRoles"))
        if None in (include_users, exclude_users, exclude_groups, include_roles, exclude_roles):
            unknown.append(name_of(policy))
            continue
        if (len(exclude_users) > MAX_EXCLUDED_USERS or exclude_groups
                or any(r in ADMIN_ROLES for r in exclude_roles)):
            findings.append(name_of(policy) + " excludes groups, admin roles or more than "
                            + str(MAX_EXCLUDED_USERS) + " users")
            continue
        if "all" in include_users and not users.get("excludeGuestsOrExternalUsers") and not exclude_roles:
            all_users = True
            used.append(name_of(policy))
        roles = [r for r in include_roles if r in ADMIN_ROLES]
        if roles:
            covered.update(roles)
            used.append(name_of(policy))
    missing = [ADMIN_ROLES[r] for r in ADMIN_ROLES if r not in covered]
    summary = {"source": "conditionalAccessPolicies", "qualifyingPolicies": used, "adminRolesNotCovered":
               [] if all_users else missing, "unreadablePolicies": unknown}
    if all_users or not missing:
        return create_response(
            result={CRITERIA_KEY: True}, validation=validation, input_summary=summary, additional_findings=findings,
            pass_reasons=["Enabled Conditional Access requires a phishing-resistant authentication strength (FIDO2, "
                          "Windows Hello for Business or multi-factor certificate only) for every administrator role: "
                          + ", ".join(used[:5])])
    return unevaluated("No enabled Conditional Access policy requires a phishing-resistant authentication strength "
                       "for every administrator role (not covered: " + ", ".join(missing[:5])
                       + ("..." if len(missing) > 5 else "") + "); Conditional Access alone does not show whether "
                       "admins sign in with a phishable method" + ("; unreadable: " + ", ".join(unknown[:3]) if unknown else ""),
                       validation, summary, findings)


def from_secure_score(data, validation):
    extra = {"scoreInPercentage": None, "count": None, "total": None}
    values = as_list(data.get("value"))
    if not values or not isinstance(values[0], dict):
        return unevaluated("Microsoft Secure Score data not available", validation, extra=extra)
    matched = [e for e in as_list(values[0].get("controlScores"))
               if isinstance(e, dict) and e.get("controlName") == CONTROL_NAME]
    if len(matched) != 1:
        return unevaluated(("Ambiguous data: " + str(len(matched)) + " objects match" if matched else "No")
                           + " Secure Score control " + CONTROL_NAME, validation, extra=extra)
    score = as_number(matched[0].get("scoreInPercentage"), None)
    count = as_number(matched[0].get("count"), 0)
    total = as_number(matched[0].get("total"), 0)
    summary = {"source": "secureScores", "hasSecureScoreData": True, "scoreInPercentage": score,
               "protectedCount": count, "totalCount": total}
    if not isinstance(score, (int, float)) or score < 0 or score > 100:
        return unevaluated("Secure Score control " + CONTROL_NAME + " has no usable scoreInPercentage", validation, summary,
                           extra=extra)
    if score < 100:
        return create_response(
            result={CRITERIA_KEY: False, "scoreInPercentage": score, "count": count, "total": total},
            validation=validation, input_summary=summary,
            fail_reasons=["Secure Score " + CONTROL_NAME + " is " + str(score) + "%: some admin-role members are not "
                          "protected by MFA at all, so admins are not limited to phishing-resistant MFA"],
            recommendations=["Require a phishing-resistant authentication strength for every admin role in "
                             "Conditional Access"])
    return unevaluated("Secure Score " + CONTROL_NAME + " is 100%: every admin is protected by MFA, but this score "
                       "does not show whether that MFA is phishing-resistant", validation, summary,
                       extra={"scoreInPercentage": score, "count": count, "total": total})


def transform(input):
    try:
        if isinstance(input, (str, bytes)):
            input = json.loads(input.decode("utf-8") if isinstance(input, bytes) else input)
        data, validation = extract_input(input)
        if not isinstance(data, dict):
            return unevaluated("Unexpected input format: expected a JSON object", validation)
        if "PSError" in data:
            api_error, recommendation = parse_api_error(str(data.get("PSError") or ""), source="Microsoft 365")
            return unevaluated(api_error, validation)
        if validation.get("status") == "failed":
            return unevaluated("Input validation failed", validation)
        if "error" in data:
            error_info = data.get("error") if isinstance(data.get("error"), dict) else {}
            return unevaluated("Microsoft Graph API error: " + str(error_info.get("code") or "unknown")[:80], validation)
        if "authenticationMethodConfigurations" in data:
            return from_methods_policy(data, validation)
        values = data.get("value")
        if isinstance(values, list) and any(isinstance(v, dict) and ("grantControls" in v or "conditions" in v)
                                            for v in values):
            if data.get("@odata.nextLink"):
                return unevaluated("The Conditional Access policy list carries a next-page link, so it is partial",
                                   validation)
            return from_ca_policies(values, validation)
        return from_secure_score(data, validation)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e)[:200])
