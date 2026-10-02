"""isRDPProtected and isMFARequiredForRemoteAccess for Microsoft Entra ID (Azure AD One-Click), from the
Conditional Access policy list (GET /v1.0/identity/conditionalAccess/policies).

Why a new file: isrdpprotected.py and ismfarequiredforremoteaccess.py count ANY enabled policy that
grants mfa (or block) for all apps, whoever it targets and whatever else it is conditioned on. On
2026-09-29 "Block legacy authentication" passed isRDPProtected at one tenant, and "Require MFA for Guest
Users" and Microsoft-managed "MFA for risky sign-ins" passed both keys at others. None of them says that
users must pass MFA.

A workforce MFA policy is enabled (report-only does not enforce), covers all apps (includeApplications
"All"; isRDPProtected also accepts the Remote Desktop / Windows Cloud Login app ids), targets all users
or user groups (not only admin roles, guests or named users), does not fire only for some risk levels,
and carries a real MFA grant ("mfa" in builtInControls or an authenticationStrength, and under operator
OR no other control that could satisfy the policy instead).

Value, per key:
- true: a workforce MFA policy targets all users (includeUsers "All"; excluded accounts are allowed and
  listed) with no platform, device-filter or client-type narrowing (client types "all", or both browser
  and mobileAppsAndDesktopClients), and is in force off the corporate network (no location condition,
  or includeLocations "All" with trusted or named locations excluded);
- not evaluated (dataCollection error, None): the only workforce MFA policies are scoped to user groups,
  platforms, client types or named locations, so whether they reach every user and sign-in cannot be
  read from this list; or no policy is enabled at all (security defaults or per-user MFA may apply);
- false: policies are enabled and none of them is a workforce MFA policy.
If either key is not evaluated the whole run reports a dataCollection error, so neither key reads a
verdict from an incomplete picture. An error or unrecognised body, or a list that still carries
@odata.nextLink (pages left unread), is not evaluated.
"""

import json
from datetime import datetime


KEYS = ("isRDPProtected", "isMFARequiredForRemoteAccess")
RDP_APP_IDS = ("a4a365df-50f1-4397-bc59-1a1564b8bb9c", "270efc09-cd0d-444b-a71f-39af4910ec45",
               "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12")


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


def create_response(result, validation, errors=(), passed=(), failed=(), summary=None):
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
                "recommendations": [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": "entra_ca_tenantwide_mfa",
                "vendor": "Microsoft Entra ID",
                "category": "Identity and Access Management",
            },
        },
    }


def as_dict(value):
    return value if isinstance(value, dict) else {}


def as_list(value):
    return value if isinstance(value, list) else []


def lowered(values):
    return [str(v).lower() for v in as_list(values)]


def requires_mfa(policy):
    grant = as_dict(policy.get("grantControls"))
    controls = lowered(grant.get("builtInControls"))
    strength = as_dict(grant.get("authenticationStrength")).get("id")
    has_mfa = "mfa" in controls or bool(strength)
    if not has_mfa:
        return False
    others = [c for c in controls if c != "mfa"] + lowered(grant.get("customAuthenticationFactors")) \
        + lowered(grant.get("termsOfUse"))
    if str(grant.get("operator") or "").upper() == "OR" and others:
        return False
    return True


ALL_RISK_LEVELS = set(["high", "medium", "low", "none"])


def risk_only(conditions):
    """True when the policy fires only for some risk levels (all four levels, 'none' included, is no narrowing)."""
    for risk in ("signInRiskLevels", "userRiskLevels", "servicePrincipalRiskLevels"):
        levels = set(lowered(conditions.get(risk)))
        if levels and not ALL_RISK_LEVELS.issubset(levels):
            return True
    return False


def unnarrowed(conditions):
    device_filter = as_dict(as_dict(conditions.get("devices")).get("deviceFilter"))
    if str(device_filter.get("rule") or "").strip():
        return False
    platforms = as_dict(conditions.get("platforms"))
    included_platforms = lowered(platforms.get("includePlatforms"))
    if (included_platforms and "all" not in included_platforms) or as_list(platforms.get("excludePlatforms")):
        return False
    apps = lowered(conditions.get("clientAppTypes"))
    if apps and "all" not in apps and not ("browser" in apps and "mobileappsanddesktopclients" in apps):
        return False
    return True


def covers_remote(conditions):
    locations = conditions.get("locations")
    if not isinstance(locations, dict):
        return True
    include = lowered(locations.get("includeLocations"))
    return not include or "all" in include


def user_scope(conditions):
    """'all' for every user, 'groups' for user groups, else '' (admins, roles, guests, named users)."""
    users = as_dict(conditions.get("users"))
    if "all" in lowered(users.get("includeUsers")):
        return "all"
    if as_list(users.get("includeGroups")) and not as_list(users.get("includeRoles")):
        return "groups"
    return ""


def classify(policy, app_ids):
    """'full', 'partial' (an MFA policy for the workforce whose reach cannot be judged here) or ''."""
    if str(policy.get("state") or "").lower() != "enabled" or not requires_mfa(policy):
        return ""
    conditions = as_dict(policy.get("conditions"))
    included_apps = lowered(as_dict(conditions.get("applications")).get("includeApplications"))
    if "all" not in included_apps and not any(app in included_apps for app in app_ids):
        return ""
    scope = user_scope(conditions)
    if not scope or risk_only(conditions):
        return ""
    if scope == "all" and unnarrowed(conditions) and covers_remote(conditions):
        return "full"
    return "partial"


def evaluate(policies):
    enabled = [p for p in policies if str(p.get("state") or "").lower() == "enabled"]
    result = {"enabledPolicyCount": len(enabled), "policyCount": len(policies)}
    for key, app_ids, names in (("isRDPProtected", RDP_APP_IDS, "rdpPolicies"),
                                ("isMFARequiredForRemoteAccess", (), "remoteAccessPolicies")):
        full = [p for p in enabled if classify(p, app_ids) == "full"]
        partial = [p for p in enabled if classify(p, app_ids) == "partial"]
        result[names] = [str(p.get("displayName") or p.get("id")) for p in full]
        result[names + "Partial"] = [str(p.get("displayName") or p.get("id")) for p in partial]
        if full:
            result[key] = True
        elif partial or not enabled:
            result[key] = None
        else:
            result[key] = False
    return result


def transform(input):
    try:
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            raise ValueError("Input validation failed")
        if not isinstance(data, dict) or "error" in data:
            raise ValueError("Microsoft did not return the Conditional Access policy list")
        policies = data.get("value")
        if not isinstance(policies, list) or any(not isinstance(p, dict) for p in policies):
            raise ValueError("The Conditional Access response carries no value array of policies")
        if "@odata.context" not in data and not policies:
            raise ValueError("An empty body with no @odata.context is not a Conditional Access policy list")
        next_link = data.get("@odata.nextLink")
        if isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"):
            raise ValueError("The policy list has more pages than were read (@odata.nextLink still present)")
        result = evaluate(policies)
        passed = []
        failed = []
        errors = []
        for key, names in (("isRDPProtected", "rdpPolicies"), ("isMFARequiredForRemoteAccess", "remoteAccessPolicies")):
            if result[key] is True:
                passed.append(key + ": MFA required of all users for all apps by " + ", ".join(result[names]))
            elif result[key] is False:
                failed.append(key + ": no enabled policy requires MFA of the workforce for all apps (only admins, roles, "
                              "guests, named users, risky sign-ins or specific apps) "
                              f"({result['enabledPolicyCount']} of {result['policyCount']} policies enabled)")
            elif result[names + "Partial"]:
                errors.append(key + ": MFA for all apps is required by policies scoped to user groups, platforms, "
                              "client types or named locations (" + ", ".join(result[names + "Partial"])
                              + "); whether they reach every user and sign-in cannot be read here")
            else:
                errors.append(key + ": no Conditional Access policy is enabled; security defaults or per-user MFA "
                              "may apply and are not read here")
        return create_response(result, validation, errors=errors, passed=passed, failed=failed, summary=result)
    except Exception as error:
        result = {}
        for key in KEYS:
            result[key] = None
        return create_response(
            result,
            {"status": "failed", "errors": [str(error)], "warnings": []},
            errors=[str(error)],
        )
