"""
Transformation: isMFAEnforcedForUsers
Vendor: Generic IDP
Category: Identity / Authentication

Evaluates the MFA status for a given IDP by checking for active MFA enrollment.

Named accounts (#101): when the Okta workflow isMFAEnforcedForUsersAccounts merges the per-user reads (users,
userFactors; see USER ACCOUNTS below) next to today's policy read (policies), the verdict is judged on policies
exactly as today's read is, and the first reason and inputSummary name the active users with no ACTIVE MFA factor.
The verdict is unchanged.
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
                # Handle list in response wrapper
                if key in data and isinstance(data.get(key), list):
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
                "vendor": "Generic",
                "category": "Identity"
            }
        }
    }


def evaluate_policies(input):
    """Today's evaluation, unchanged."""
    criteriaKey = "isMFAEnforcedForUsers"

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

        # Handle list input (from response wrapper or direct list)
        if isinstance(data, list):
            items = data
        else:
            items = []

        # Find active MFA enrollment entries
        mfa_enrolled = [
            obj for obj in items
            if isinstance(obj, dict)
            and 'type' in obj and str(obj['type']).lower() == "mfa_enroll"
            and 'status' in obj and str(obj['status']).lower() == "active"
        ]

        is_enforced = len(mfa_enrolled) > 0

        if is_enforced:
            pass_reasons.append(f"MFA is enforced with {len(mfa_enrolled)} active enrollments")
        else:
            fail_reasons.append("No users enrolled in MFA")
            recommendations.append("Enable MFA enrollment for all users")

        return create_response(
            result={criteriaKey: is_enforced},
            validation=validation,
            pass_reasons=pass_reasons,
            fail_reasons=fail_reasons,
            recommendations=recommendations,
            input_summary={"activeMfaEnrollments": len(mfa_enrolled), "totalItems": len(items)}
        )

    except Exception as e:
        return create_response(
            result={criteriaKey: False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=[f"Transformation error: {str(e)}"]
        )


# USER ACCOUNTS (#101). The isMFAEnforcedForUsersAccounts workflow merges two per-user reads next to the reads
# the verdict uses:
#   users        GET /api/v1/users?limit=200&filter=status eq "ACTIVE", link_header paging, at most 5 pages
#                (1,000 users; okta.users.read)
#   userFactors  GET /api/v1/users/{id}/factors per user, in users order (okta.users.read; not paginated)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/User/
#       https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserFactor/
# The userFactors step may carry the opt-in iterate fields (Integration-Service #1402). Then a user whose read
# failed holds an error record {"error": true, "statusCode", "item", "errorType"} in its own slot, and the merge
# carries itemErrors, iterateTruncated and iterateStats.userFactors {itemsTotal, itemsProcessed, itemErrors,
# iterateTruncated}. Without them (today's iterate) every slot is that user's factor list, or a mapped vendor
# error {"vendorErrorAsResponse": ...}.
# An affected user is an active user with no ACTIVE factor of any type (not enrolled in MFA). Only users whose
# factor list was read are judged or named. Okta lists only the factors in the highest-priority enrollment policy
# (evaluated for the reading admin), so "no factor" can be a false positive; the line says so.
# Fails closed on the naming only: a user list that is missing or an error, a user without an id, a factor list
# for another user, or results that do not line up with the user list name no one. A capped or partly failed
# read names only the users read and says what was not read; it never claims the whole estate.
# Same shape as #891 / #905 / #909: the first reason names at most USER_MAX_NAMED, then "and N more";
# inputSummary.affectedAccounts carries at most USER_MAX_AFFECTED, with the full count in affectedAccountCount.
# The verdict never reads any of this, and without the users read (today's workflow) the output is exactly what
# it was.
USER_MAX_NAMED = 20
USER_MAX_AFFECTED = 50
USER_READ_CAP = 1000
USER_SCOPE = "Okta (active users)"
USER_FACTOR_CAVEAT = ("Okta lists only the factors in the highest-priority enrollment policy (evaluated for the "
                      "reading admin), so 'no factor' can be a false positive")


def thousands(number):
    text = str(int(number))
    out = ""
    while len(text) > 3:
        out = "," + text[-3:] + out
        text = text[:-3]
    return text + out


def count_or_none(value):
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def user_read_error(block):
    """A short reason when a read came back as an error instead of data, else None."""
    if not isinstance(block, dict):
        return None
    marked = block.get("vendorErrorAsResponse")
    if isinstance(marked, dict):
        return "Okta answered HTTP " + str(marked.get("status"))[:8]
    if block.get("error") or block.get("errorCode") or block.get("errorSummary"):
        return "the read returned an error"
    return None


def user_factor_belongs(fac, user_id):
    """False when a factor's own links point at another user (the per-user results are out of line)."""
    links = fac.get("_links")
    if not isinstance(links, dict):
        return True
    for name in ("self", "user"):
        link = links.get(name)
        href = link.get("href") if isinstance(link, dict) else None
        if isinstance(href, str) and "/users/" in href and ("/users/" + user_id + "/") not in (href + "/"):
            return False
    return True


def user_login(user, user_id):
    profile = user.get("profile") if isinstance(user.get("profile"), dict) else {}
    name = profile.get("login") or profile.get("email") or user_id
    return str(name).strip()[:100]


def users_not_named(why):
    return {"read": False, "why": why}


def user_accounts_data(raw):
    """The merged body the per-user reads sit in: JSON text decoded and the usual wrappers removed."""
    value = raw
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value)
    for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
        if isinstance(value, dict) and wrapper in value and "users" not in value:
            value = value[wrapper]
    return value


def user_accounts(data):
    """None when the per-user reads are not in the input; otherwise who is affected, or why no one is named."""
    if not isinstance(data, dict) or "users" not in data:
        return None
    users = data.get("users")
    err = user_read_error(users)
    if err:
        return users_not_named("the active user list was not read (" + err + ")")
    if not isinstance(users, list):
        return users_not_named("the active user list was not read")
    if not users:
        return users_not_named("Okta returned no active users")
    ids = []
    for row in users:
        user_id = row.get("id") if isinstance(row, dict) else None
        if not isinstance(user_id, str) or not user_id.strip():
            return users_not_named("a user record carries no id, so the per-user factor results cannot be lined up")
        ids.append(user_id.strip())
    factors = data.get("userFactors")
    if factors is None:
        return users_not_named("the per-user factor read is missing")
    err = user_read_error(factors)
    if err:
        return users_not_named("the per-user factor read was not returned (" + err + ")")
    if not isinstance(factors, list):
        return users_not_named("the per-user factor read was not returned")
    all_stats = data.get("iterateStats")
    stats = all_stats.get("userFactors") if isinstance(all_stats, dict) else None
    if not isinstance(stats, dict):
        stats = {}
    truncated = stats.get("iterateTruncated") is True or data.get("iterateTruncated") is True
    checked = len(factors)
    total = len(ids)
    items_total = count_or_none(stats.get("itemsTotal"))
    if items_total is not None and items_total > total:
        total = items_total
    out_of_line = ("the per-user factor results do not line up with the user list ("
                   + thousands(checked) + " results for " + thousands(len(ids)) + " users)")
    if checked > len(ids):
        return users_not_named(out_of_line)
    if checked < len(ids):
        processed = count_or_none(stats.get("itemsProcessed"))
        if checked == 0 or not truncated or (processed is not None and processed != checked):
            return users_not_named(out_of_line)
    # More than USER_READ_CAP users is never judged past the cap, whatever the read returned.
    if checked > USER_READ_CAP:
        checked = USER_READ_CAP
    affected = []
    judged = 0
    unread = 0
    for index in range(checked):
        user_id = ids[index]
        user = users[index]
        slot = factors[index]
        if not isinstance(slot, list):
            item = slot.get("item") if isinstance(slot, dict) else None
            if isinstance(item, str) and item.strip() and item.strip() != user_id:
                return users_not_named("a per-user error record belongs to another user")
            unread = unread + 1
            continue
        active = False
        for fac in slot:
            if not isinstance(fac, dict) or not user_factor_belongs(fac, user_id):
                return users_not_named("a user's factor list does not belong to that user")
            if str(fac.get("status") or "").strip().upper() == "ACTIVE":
                active = True
        status = user.get("status")
        if status is not None and str(status).strip().upper() != "ACTIVE":
            continue
        judged = judged + 1
        if not active:
            affected.append(user_login(user, user_id))
    reported = count_or_none(stats.get("itemErrors"))
    if reported is None:
        reported = count_or_none(data.get("itemErrors"))
    if reported is not None and reported > unread:
        unread = reported
    if judged == 0:
        return users_not_named("no active user's factor list was read (" + thousands(unread) + " could not be read)")
    return {"read": True, "judged": judged, "affected": affected, "unread": unread, "checked": checked,
            "total": total, "listCapped": total == len(ids) and len(ids) == USER_READ_CAP}


def user_name_list(items):
    """At most USER_MAX_NAMED identifiers, then 'and N more'."""
    shown = ", ".join(items[:USER_MAX_NAMED])
    if len(items) > USER_MAX_NAMED:
        shown = shown + " and " + str(len(items) - USER_MAX_NAMED) + " more"
    return shown


def user_read_partial(accounts):
    return accounts["checked"] < accounts["total"] or accounts["listCapped"] or accounts["unread"] > 0


def user_accounts_line(accounts):
    """One line naming the tool and its scope."""
    if not accounts["read"]:
        return USER_SCOPE + ": accounts not named, " + accounts["why"]
    line = (USER_SCOPE + ": " + thousands(len(accounts["affected"])) + " of " + thousands(accounts["judged"])
            + " active users read have no ACTIVE MFA factor enrolled")
    if accounts["affected"]:
        line = line + ": " + user_name_list(accounts["affected"])
    notes = []
    if accounts["checked"] < accounts["total"]:
        notes.append("the account read is partial: only the first " + thousands(accounts["checked"]) + " of "
                     + thousands(accounts["total"]) + " active users were checked, so more may be affected")
    elif accounts["listCapped"]:
        notes.append("the account read may be partial: " + thousands(USER_READ_CAP) + " active users were read, "
                     + "the most the user list read returns, so more may exist and be affected")
    if accounts["unread"] > 0:
        notes.append(thousands(accounts["unread"]) + (" user" if accounts["unread"] == 1 else " users")
                     + " could not be read and are not named")
    if accounts["affected"]:
        notes.append(USER_FACTOR_CAVEAT)
    if notes:
        line = line + "; " + "; ".join(notes)
    return line


def with_user_accounts(response, raw, key):
    """Adds the line to the first reason and the names to inputSummary. Verdict fields are not touched.

    All of the naming runs inside this one guard: every read and type check comes before the first write, and
    any surprise returns the response exactly as it came in.
    """
    try:
        accounts = user_accounts(user_accounts_data(raw))
        if accounts is None:
            return response
        line = user_accounts_line(accounts)
        if not isinstance(response, dict) or not isinstance(line, str):
            return response
        result = response["transformedResponse"]
        info = response["additionalInfo"]
        evaluation = info["evaluation"]
        summary = info["transformation"]["inputSummary"]
        fail_reasons = evaluation["failReasons"]
        pass_reasons = evaluation["passReasons"]
        if not isinstance(result, dict) or not isinstance(summary, dict):
            return response
        if not isinstance(fail_reasons, list) or not isinstance(pass_reasons, list):
            return response
        passed = result.get(key) is True
        reasons = None
        if fail_reasons:
            reasons = fail_reasons
        elif passed and pass_reasons and (not accounts["read"] or accounts["affected"] or user_read_partial(accounts)):
            reasons = pass_reasons
        first = None
        if reasons is not None:
            if not isinstance(reasons[0], str):
                return response
            first = reasons[0] + "; " + line
        affected = None
        if accounts["read"]:
            affected = list(accounts["affected"])
        if affected is not None:
            summary["affectedAccounts"] = affected[:USER_MAX_AFFECTED]
            summary["affectedAccountCount"] = len(affected)
        if first is not None:
            reasons[0] = first
        return response
    except Exception:
        return response


def user_accounts_input(raw):
    """For the isMFAEnforcedForUsersAccounts merge: {"policies": the body today's read hands this file, with the
    same validation wrapper, "accounts": the merge}. None for any other input, which then runs exactly as before."""
    try:
        value = raw
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value)
        data, validation = extract_input(value)
        if not isinstance(data, dict) or "policies" not in data or "users" not in data:
            return None
        policies = data["policies"]
        if isinstance(value, dict) and "data" in value and "validation" in value:
            policies = {"data": policies, "validation": validation}
        return {"policies": policies, "accounts": data}
    except Exception:
        return None


def transform(input):
    merged = user_accounts_input(input)
    if merged is None:
        return evaluate_policies(input)
    return with_user_accounts(evaluate_policies(merged["policies"]), merged["accounts"], "isMFAEnforcedForUsers")
