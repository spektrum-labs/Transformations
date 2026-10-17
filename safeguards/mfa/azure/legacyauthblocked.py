"""
Transformation: legacyAuthBlocked
Vendor: Microsoft Entra ID  |  Category: Multifactor Authentication
Evaluates: Whether legacy authentication protocols are blocked

Legacy clients are the Conditional Access clientAppTypes exchangeActiveSync and other (POP, IMAP, SMTP AUTH and
other basic-auth protocols). The verdict is unchanged: True when at least one enabled policy blocks them.

Named evidence (#101): the reasons name the accounts the block does not reach, capped at 20 plus "and N more":
every user, group and directory role named in an enabled blocking policy that no blocking policy covers (a policy
covers a principal when it includes it, directly or through All users, and does not exclude it), and the user,
group or role scope when no blocking policy targets all users. Coverage is computed on the ids as the policies
list them; group and role membership is not expanded. Microsoft Graph returns object ids, not names, so the
reasons carry ids prefixed with their kind.

Coverage (Entra MFA review, overstated passes, for J.J.'s review): a block counts only when the blocking policies
together reach all users. That needs a blocking policy that includes All users and does not exclude everyone, and,
after crediting every principal another blocking policy includes, at most MAX_BREAK_GLASS named accounts left
outside (the emergency-access limit isMFAEnforcedForUsers allows), no group or directory role left outside, and
guests not excluded by every All-users block. Otherwise:
- blocks that reach only named users (no All users, no group or role): False, the block misses everyone else;
- blocks whose reach depends on group or role membership (scoped to groups or roles, or leaving a group, a role,
  guests or more than MAX_BREAK_GLASS accounts outside): not evaluated (value None, dataCollection.status
  "error"). Membership is not read here, so coverage cannot be confirmed either way.
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
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0", "transformationId": "legacyAuthBlocked", "vendor": "Microsoft Entra ID", "category": "Multifactor Authentication"}
        }
    }


MAX_NAMED = 20
MAX_BREAK_GLASS = 2
LEGACY_CLIENTS = ['exchangeActiveSync', 'other']
EXCLUDE_FIELDS = [('excludeUsers', 'user'), ('excludeGroups', 'group'), ('excludeRoles', 'role')]
INCLUDE_FIELDS = [('includeUsers', 'user'), ('includeGroups', 'group'), ('includeRoles', 'role')]
# Graph keywords, not principals.
SPECIAL_PRINCIPALS = {'user:All', 'user:None', 'user:GuestsOrExternalUsers', 'group:All', 'role:All'}


def name_list(items):
    """At most MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:MAX_NAMED])
    if len(items) > MAX_NAMED:
        shown = shown + " and " + str(len(items) - MAX_NAMED) + " more"
    return shown


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


def lowered(values):
    return [str(v).strip().lower() for v in values] if isinstance(values, list) else []


def block_coverage(legacy_block, all_users, scoped, exempt):
    """("all", ""), ("named", reason) or ("unproven", reason) for the blocking policies together (see the header)."""
    if not all_users:
        if [x for x in scoped if x.startswith("group:") or x.startswith("role:")]:
            return "unproven", ("the blocking policies target groups or directory roles, not all users, and their "
                                "membership is not read")
        return "named", "the blocking policies target named accounts only, not all users"
    everyone_excluded = True
    guests_inside = False
    for p in legacy_block:
        users = p.get('conditions', {}).get('users', {})
        if not isinstance(users, dict) or "all" not in lowered(users.get('includeUsers')):
            continue
        excluded = lowered(users.get('excludeUsers'))
        if "all" in excluded:
            continue
        everyone_excluded = False
        if "guestsorexternalusers" not in excluded and not users.get('excludeGuestsOrExternalUsers'):
            guests_inside = True
    if everyone_excluded:
        return "named", "every All-users blocking policy also excludes all users"
    outside = []
    if not guests_inside:
        outside.append("guests or external users")
    groups = [x for x in exempt if x.startswith("group:")]
    roles = [x for x in exempt if x.startswith("role:")]
    accounts = [x for x in exempt if x.startswith("user:")]
    if groups:
        outside.append(str(len(groups)) + " group(s)")
    if roles:
        outside.append(str(len(roles)) + " directory role(s)")
    if len(accounts) > MAX_BREAK_GLASS:
        outside.append(str(len(accounts)) + " named accounts (more than " + str(MAX_BREAK_GLASS)
                       + " emergency-access accounts)")
    if outside:
        return "unproven", "the block leaves " + ", ".join(outside) + " outside every blocking policy"
    return "all", ""


def evaluate(data):
    """Core evaluation logic."""
    try:
        policies = data.get('value', [])
        legacy_block = [
            p for p in policies
            if p.get('state') == 'enabled'
            and any(
                client_type in p.get('conditions', {}).get('clientAppTypes', [])
                for client_type in LEGACY_CLIENTS
            )
            and p.get('grantControls', {}).get('builtInControls') == ['block']
        ]
        result = {
            "legacyAuthBlocked": len(legacy_block) > 0,
            "blockingPolicies": len(legacy_block)
        }
        if legacy_block:
            # Coverage per principal: a principal is blocked when at least one blocking policy includes it
            # (directly or through All users) and that same policy does not exclude it. Every principal named
            # in any blocking policy is checked, so an account excluded from the All-users block and not
            # included by a scoped one is named, even when another policy does not exclude it.
            all_users = False
            scoped = []
            rules = []
            candidates = []
            for p in legacy_block:
                users = p.get('conditions', {}).get('users', {})
                excluded = set(principals(users, EXCLUDE_FIELDS))
                included = principals(users, INCLUDE_FIELDS)
                includes_all = "user:All" in included
                if includes_all:
                    all_users = True
                rules.append((includes_all, set(included), excluded))
                for x in included:
                    if x not in scoped:
                        scoped.append(x)
                for x in list(excluded) + included:
                    if x not in SPECIAL_PRINCIPALS and x not in candidates:
                        candidates.append(x)
            exempt = sorted(
                x for x in candidates
                if not any((includes_all or x in included) and x not in excluded
                           for includes_all, included, excluded in rules)
            )
            result["exemptPrincipals"] = len(exempt)
            result["exemptPrincipalIds"] = exempt
            if not all_users:
                result["blockScope"] = sorted(scoped)
            result["coverage"] = block_coverage(legacy_block, all_users, scoped, exempt)
        return result
    except Exception as e:
        return {"legacyAuthBlocked": False, "error": str(e)}


def transform(input):
    criteriaKey = "legacyAuthBlocked"
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

        eval_result = evaluate(data)
        result_value = eval_result.get(criteriaKey, False)
        exempt = eval_result.get("exemptPrincipalIds") or []
        scope = eval_result.get("blockScope")
        coverage, coverage_why = eval_result.get("coverage") or ("all", "")
        extra_fields = {k: v for k, v in eval_result.items()
                        if k not in [criteriaKey, "error", "exemptPrincipalIds", "blockScope", "coverage"]}
        if result_value and coverage != "all":
            summary = {criteriaKey: None if coverage == "unproven" else False, **extra_fields,
                       "exemptPrincipalIds": exempt[:MAX_NAMED]}
            if scope is not None:
                summary["blockScope"] = scope[:MAX_NAMED]
            named = ""
            if exempt or scope is not None:
                named = "; named: " + (name_list(exempt) if exempt else name_list(scope or []) or "no one")
            if coverage == "unproven":
                return create_response(
                    result={criteriaKey: None, **extra_fields},
                    validation=validation,
                    api_errors=["Legacy clients are blocked by " + str(extra_fields.get("blockingPolicies", 0))
                                + " enabled Conditional Access policy(ies), but coverage of all users cannot be "
                                "confirmed: " + coverage_why + named],
                    input_summary=summary)
            return create_response(
                result={criteriaKey: False, **extra_fields},
                validation=validation,
                fail_reasons=[f"{criteriaKey} check failed: no enabled Conditional Access policy blocks legacy "
                              "clients (POP, IMAP, SMTP AUTH, Exchange ActiveSync) for all users: " + coverage_why
                              + named + ", so every other account can still use them"],
                recommendations=["Target the legacy-authentication block at All users, excluding at most "
                                 + str(MAX_BREAK_GLASS) + " documented break-glass accounts"],
                input_summary=summary)
        summary = {criteriaKey: result_value, **extra_fields}
        if exempt:
            summary["exemptPrincipalIds"] = exempt[:MAX_NAMED]
        if scope is not None:
            summary["blockScope"] = scope[:MAX_NAMED]

        pass_reasons = []
        fail_reasons = []
        recommendations = []

        if result_value:
            reason = (f"{criteriaKey} check passed: {extra_fields.get('blockingPolicies', 0)} enabled Conditional "
                      "Access policy(ies) block legacy clients (POP, IMAP, SMTP AUTH, Exchange ActiveSync)")
            if exempt:
                reason = (reason + "; " + str(len(exempt)) + " account(s), group(s) or role(s) not covered by any "
                          "blocking policy can still use them: " + name_list(exempt))
            if scope is not None:
                reason = (reason + "; no blocking policy targets all users, the block reaches only: "
                          + (name_list(scope) if scope else "no one named"))
            pass_reasons.append(reason)
            for k, v in extra_fields.items():
                pass_reasons.append(f"{k}: {v}")
            if exempt or scope is not None:
                recommendations.append("Review the accounts named above: remove each exclusion that is not a "
                                       "documented break-glass account, and target the block at All users")
        else:
            if "error" in eval_result:
                fail_reasons.append(f"{criteriaKey} check failed")
                fail_reasons.append(eval_result["error"])
            else:
                fail_reasons.append(f"{criteriaKey} check failed: no enabled Conditional Access policy blocks "
                                    "legacy clients (POP, IMAP, SMTP AUTH, Exchange ActiveSync), so every account "
                                    "in the tenant can use them")
            recommendations.append(f"Review Microsoft Entra ID configuration for {criteriaKey}")

        return create_response(
            result={criteriaKey: result_value, **extra_fields},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary=summary
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )
