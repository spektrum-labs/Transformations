"""
Transformation: legacyAuthBlocked
Vendor: Microsoft Entra ID  |  Category: Multifactor Authentication
Evaluates: Whether legacy authentication protocols are blocked

Legacy clients are the Conditional Access clientAppTypes exchangeActiveSync and other (POP, IMAP, SMTP AUTH and
other basic-auth protocols). The verdict is unchanged: True when at least one enabled policy blocks them.

Named evidence (#101): the reasons name the accounts the block does not reach, capped at 20 plus "and N more":
the users, groups and directory roles excluded from every enabled blocking policy (an account excluded from one
policy but caught by another is still blocked), and the user, group or role scope when no blocking policy targets
all users. Microsoft Graph returns object ids, not names, so the reasons carry ids prefixed with their kind.
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
LEGACY_CLIENTS = ['exchangeActiveSync', 'other']
EXCLUDE_FIELDS = [('excludeUsers', 'user'), ('excludeGroups', 'group'), ('excludeRoles', 'role')]
INCLUDE_FIELDS = [('includeUsers', 'user'), ('includeGroups', 'group'), ('includeRoles', 'role')]


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
            # An account is unblocked only when every blocking policy excludes it.
            excluded = None
            all_users = False
            scoped = []
            for p in legacy_block:
                users = p.get('conditions', {}).get('users', {})
                this_excluded = principals(users, EXCLUDE_FIELDS)
                excluded = this_excluded if excluded is None else [x for x in excluded if x in this_excluded]
                included = principals(users, INCLUDE_FIELDS)
                if "user:All" in included:
                    all_users = True
                for x in included:
                    if x not in scoped:
                        scoped.append(x)
            exempt = sorted(set(excluded or []))
            result["exemptPrincipals"] = len(exempt)
            result["exemptPrincipalIds"] = exempt
            if not all_users:
                result["blockScope"] = sorted(scoped)
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
        extra_fields = {k: v for k, v in eval_result.items()
                        if k not in [criteriaKey, "error", "exemptPrincipalIds", "blockScope"]}
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
                reason = (reason + "; " + str(len(exempt)) + " account(s), group(s) or role(s) excluded from every "
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
