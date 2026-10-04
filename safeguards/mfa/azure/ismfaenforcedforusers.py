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
  entra_strongauth_methods.py). It is never a FAIL. Seen at one estate, where a tenant
  that requires Duo through Conditional Access read "No MFA authentication methods enabled";
- the authentication methods policy or the Conditional Access policies were not read (error
  envelope, no authenticationMethodConfigurations array, no policy list), or input validation
  failed: a read that failed is not evidence either way.

FAIL stays only when both were read and they show no MFA: no Microsoft MFA method and no
external method enabled, or, with no external method enabled, no enabled Conditional Access
policy requiring MFA for users. An external method (e.g. Duo) with no Conditional Access policy
requiring MFA reads not evaluated, not FAIL.
"""

import json
from datetime import datetime

# Two independent switches (4 Oct 2026). With EXCLUDE_RISK_CONDITIONED = False and ALL_USERS_TARGET_MODE = "off" the
# output is byte-identical to the behaviour before they existed. J.J. chose (a) + (b-unevaluated) on 4 Oct 2026:
# EXCLUDE_RISK_CONDITIONED = True, ALL_USERS_TARGET_MODE = "unevaluated".
#
# EXCLUDE_RISK_CONDITIONED: a policy with a non-empty signInRiskLevels or userRiskLevels condition fires only on
#   risk (for example the Microsoft-managed "Multifactor authentication and reauthentication for risky sign-ins"
#   policy, or a user-risk password-change policy), so it does not enforce MFA for users' sign-ins. When True,
#   such policies do not count.
# ALL_USERS_TARGET_MODE: "off" (default), "unevaluated" or "not_met". When not "off", a policy counts only if
#   conditions.users.includeUsers contains "All". Group-targeted policies are set aside (their reach is not read
#   here; entra_ca_mfa_coverage.py resolves group membership for the remote-access keys). Exclusions follow the
#   repo convention of entra_ca_mfa_coverage.py (master review, 3 Oct 2026): at most MAX_EXCLUDED_ACCOUNTS user
#   accounts excluded by name in total per policy (emergency-access / break-glass) are allowed; any excluded group,
#   directory role, guests or external users, or "All" in excludeUsers sets the policy aside.
#   - "not_met": with no counting policy left, the key reads False (as before for "no policy").
#   - "unevaluated": with MFA methods enabled and no counting policy left, but at least one policy set aside for
#     its target or its exclusions (not for risk), the key reads not evaluated: MFA is required only for groups
#     (or with exclusions) whose membership is not read, so coverage of all users cannot be confirmed. It never
#     reads False on group policies alone.
# Set-aside policies are named in the fail reason (at most SET_ASIDE_SHOWN, then "and N more"; names cut to
# SET_ASIDE_NAME_CHARS) and returned as policiesSetAside.
EXCLUDE_RISK_CONDITIONED = True
ALL_USERS_TARGET_MODE = "unevaluated"
RISK_REASON = "fires only on sign-in or user risk"
MAX_EXCLUDED_ACCOUNTS = 2
SET_ASIDE_SHOWN = 5
SET_ASIDE_NAME_CHARS = 80
USER_KEYWORDS = ("all", "none", "guestsorexternalusers")


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


def short_name(value):
    name = str(value)
    return name if len(name) <= SET_ASIDE_NAME_CHARS else name[:SET_ASIDE_NAME_CHARS - 3] + "..."


def risk_conditioned(conditions):
    for key in ("signInRiskLevels", "userRiskLevels"):
        levels = conditions.get(key)
        if isinstance(levels, list) and len(levels) > 0:
            return True
    return False


def all_users_exclusions(users):
    """What an "All users" policy excludes beyond at most MAX_EXCLUDED_ACCOUNTS named accounts; '' when nothing."""
    found = []
    excluded = users.get("excludeUsers")
    if excluded is not None and not isinstance(excluded, list):
        return "users in a list that cannot be read"
    raw = [str(v).strip().lower() for v in (excluded or [])]
    if "all" in raw:
        found.append("all users")
    if "guestsorexternalusers" in raw or users.get("excludeGuestsOrExternalUsers"):
        found.append("guests or external users")
    if users.get("excludeGroups"):
        found.append("a group")
    if users.get("excludeRoles"):
        found.append("a directory role")
    named = [v for v in raw if v and v not in USER_KEYWORDS]
    if len(named) > MAX_EXCLUDED_ACCOUNTS:
        found.append(f"{len(named)} user accounts (more than {MAX_EXCLUDED_ACCOUNTS})")
    return ", ".join(found)


def set_aside_reason(conditions, users, targets_all):
    if EXCLUDE_RISK_CONDITIONED and risk_conditioned(conditions):
        return RISK_REASON
    if ALL_USERS_TARGET_MODE in ("unevaluated", "not_met"):
        if not targets_all:
            return "targets groups, not all users"
        excluded = all_users_exclusions(users)
        if excluded:
            return "excludes " + excluded
    return ""


def set_aside_text(entries):
    shown = ['"' + name + '" (' + why + ")" for name, why in entries[:SET_ASIDE_SHOWN]]
    more = len(entries) - SET_ASIDE_SHOWN
    return "policies set aside: " + ", ".join(shown) + (f" and {more} more" if more > 0 else "")


# #101: findings name the affected accounts (same shape as legacyauthblocked.py). The first reason names
# at most MAX_NAMED, then "and N more"; inputSummary.affectedAccounts carries at most MAX_AFFECTED, with
# the full count in affectedAccountCount. The verdict never reads them.
MAX_NAMED = 20
MAX_AFFECTED = 50


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


def affected_line(scope, affected, total, what):
    """One line naming the tool and its scope: 'Microsoft Entra ID (<scope>): N of M <what>: a, b and K more'."""
    return "Microsoft Entra ID (%s): %d of %d %s: %s" % (scope, len(affected), total, what, name_list(affected))


def with_affected(summary, affected):
    summary["affectedAccounts"] = affected[:MAX_AFFECTED]
    summary["affectedAccountCount"] = len(affected)
    return summary


EXCLUDE_FIELDS = [('excludeUsers', 'user'), ('excludeGroups', 'group'), ('excludeRoles', 'role')]
INCLUDE_FIELDS = [('includeUsers', 'user'), ('includeGroups', 'group'), ('includeRoles', 'role')]
# Graph keywords, not principals.
SPECIAL_PRINCIPALS = {'user:All', 'user:all', 'user:None', 'user:GuestsOrExternalUsers', 'group:All', 'role:All'}


def principals(users, fields):
    found = []
    for field, kind in fields:
        values = users.get(field) if isinstance(users, dict) else None
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value.strip():
                found.append(kind + ":" + value.strip()[:64])
    return found


def mfa_coverage(user_conditions):
    """Per-principal coverage across the MFA-for-users policies (same rule as legacyauthblocked.py): a
    principal is covered when at least one policy includes it (directly or through All users) and that same
    policy does not exclude it. Returns (uncovered principals, principals named, include scope or None when a
    policy targets all users). Group and role membership is not expanded."""
    all_users = False
    scope = []
    rules = []
    candidates = []
    for users in user_conditions:
        excluded = set(principals(users, EXCLUDE_FIELDS))
        included = principals(users, INCLUDE_FIELDS)
        includes_all = "user:All" in included or "user:all" in included
        if includes_all:
            all_users = True
        rules.append((includes_all, set(included), excluded))
        for x in included:
            if x not in scope:
                scope.append(x)
        for x in list(excluded) + included:
            if x not in SPECIAL_PRINCIPALS and x not in candidates:
                candidates.append(x)
    uncovered = sorted(
        x for x in candidates
        if not any((includes_all or x in included) and x not in excluded
                   for includes_all, included, excluded in rules)
    )
    return uncovered, len(candidates), (None if all_users else sorted(scope))


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
        set_aside = []
        mfa_user_conditions = []

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
                why = set_aside_reason(conditions, users, targets_all)
                if why:
                    set_aside.append((short_name(policy.get('displayName')), why))
                    continue
                policies_enforcing_mfa_all_users.append(policy.get('displayName'))
                mfa_user_conditions.append(users)

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
        if set_aside:
            details["policiesSetAside"] = [name + " (" + why + ")" for name, why in set_aside]

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

        scope_unknown = [(name, why) for name, why in set_aside if why != RISK_REASON]
        if (ALL_USERS_TARGET_MODE == "unevaluated" and methods_available and not mfa_enforced_for_users
                and scope_unknown):
            names = ", ".join('"' + name + '"' for name, _ in scope_unknown[:SET_ASIDE_SHOWN])
            more = len(scope_unknown) - SET_ASIDE_SHOWN
            return not_evaluated(
                criteriaKey,
                "MFA is required only by policies scoped to groups or with exclusions (" + names
                + (f" and {more} more" if more > 0 else "") + "); group membership is not read, so coverage of "
                "all users cannot be confirmed; " + set_aside_text(set_aside),
                validation, input_summary=input_summary, extra=details)

        is_enforced = methods_available and mfa_enforced_for_users
        uncovered, named_total, mfa_scope = mfa_coverage(mfa_user_conditions)
        input_summary = with_affected(dict(input_summary), uncovered)
        if mfa_enforced_for_users and mfa_scope is not None:
            input_summary["mfaScope"] = mfa_scope[:MAX_NAMED]

        if methods_available:
            pass_reasons.append(f"MFA methods enabled: {', '.join(enabled_methods)}")
        else:
            fail_reasons.append("No MFA authentication methods enabled at the tenant level")
            recommendations.append("Enable MFA methods (Microsoft Authenticator, FIDO2, or Software OATH) in authentication methods policy")

        if mfa_enforced_for_users:
            pass_reasons.append(f"MFA enforced for users via {len(policies_enforcing_mfa_all_users)} policies: {', '.join(str(p) for p in policies_enforcing_mfa_all_users[:3])}")
        else:
            fail_reasons.append("No enabled conditional access policies requiring MFA for all users"
                                + ("; " + set_aside_text(set_aside) if set_aside else ""))
            recommendations.append("Create a conditional access policy requiring MFA that targets All Users or relevant groups")

        if is_enforced and (uncovered or mfa_scope is not None):
            line = ""
            if uncovered:
                line = "; " + affected_line("Conditional Access policies requiring MFA for users", uncovered,
                                            named_total, "users, groups or roles named in those policies are "
                                            "covered by none of them")
            if mfa_scope is not None:
                line = (line + "; no MFA policy targets all users, MFA reaches only: "
                        + (name_list(mfa_scope) if mfa_scope else "no one named"))
            pass_reasons[0] = pass_reasons[0] + line
            recommendations.append("Review the accounts named above: remove each MFA exclusion that is not a "
                                   "documented break-glass account, and target the MFA policy at All users")

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
