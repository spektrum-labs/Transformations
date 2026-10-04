# ismfaenforcedforusers.py - Okta (Identity Engine and Classic)
#
# Method: workflow getMfaPolicyRules (Integration-Service), four GETs:
#   GET /api/v1/policies?type=OKTA_SIGN_ON        -> signOnPolicies   (global session policies)
#   GET /api/v1/policies/{policyId}/rules         -> signOnRules      (one list per policy, same order)
#   GET /api/v1/policies?type=ACCESS_POLICY       -> accessPolicies   (authentication policies)
#   GET /api/v1/policies/{policyId}/rules         -> accessRules      (one list per policy, same order)
# Docs: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Policy/
#   listPolicies, listPolicyRules (scope okta.policies.read). Rule schemas:
#   AccessPolicyRule.actions.appSignOn.{access, verificationMethod.{type, factorMode}}
#   OktaSignOnPolicyRule.actions.signon.{access, requireFactor}
#
# Replaces the MFA_ENROLL read (safeguards/86ded564.../ismfaenforcedforusers.py). That read passed
# on Okta's undeletable system Default enrollment policy, which exists in every org and says
# nothing about whether a second factor is ever demanded at sign-in.
#
# Named accounts (#101): when the workflow isMFAEnforcedForUsersAccounts also merges the per-user reads (users,
# userFactors; see USER ACCOUNTS below) next to the four policy reads, the first reason and inputSummary name the
# active users with no ACTIVE MFA factor. Both verdicts (isMFAEnforcedForUsers, isMFAEnabled) are unchanged.

import json


def transform(input):
    """
    Returns two keys from one read (the RTA points both criteria at this file):
      isMFAEnforcedForUsers - True only when no path into any app accepts a single factor.
      isMFAEnabled          - True when at least one allowing sign-on rule requires two factors.

    Identity Engine (at least one ACTIVE authentication policy whose _embedded.resourceType is APP
    or absent): every ACTIVE rule that ALLOWs access, in every ACTIVE app authentication policy,
    has verificationMethod type ASSURANCE with factorMode 2FA. A rule's conditions (network zone,
    group, device) are ignored on purpose: a 1FA rule scoped to one zone is still a 1FA path.
    Policies with resourceType END_USER_ACCOUNT_MANAGEMENT (enrolment, recovery, unlock) are not
    app sign-in and are reported, not judged.

    Classic Engine (the authentication policy list is readable but holds no active app policy):
    every ACTIVE rule that ALLOWs access
    in every ACTIVE global session (OKTA_SIGN_ON) policy has requireFactor true.

    Fails closed on: an error body, missing policy or rule lists, a rule list whose length does not
    match its policy list, an active policy with no active rules, and any verification method this
    code does not recognise (AUTH_METHOD_CHAIN, ID_PROOFING).

    Does not prove: which authenticators can satisfy the second factor (see authTypesAllowed), or
    that every user has enrolled one.
    """
    key = "isMFAEnforcedForUsers"
    checks = MFA_CHECKS()
    try:
        state = checks["evaluate"](input)
    except Exception as e:
        return checks["respond"]({key: False, "isMFAEnabled": False}, [], ["Transformation error: " + str(e)], {}, [str(e)])
    ok = state["error"] is None and state["enforced"]
    enabled = state["error"] is None and state["enabled"]
    passes = []
    fails = []
    if state["error"] is not None:
        fails.append(state["error"])
    elif ok:
        passes.append(state["summary"])
    else:
        fails.append(state["summary"])
        for weak in state["weak"][:10]:
            fails.append("Single-factor path: " + weak)
    return with_user_accounts(checks["respond"]({key: ok, "isMFAEnabled": enabled}, passes, fails, state["inputSummary"], []),
                              input, key)


def MFA_CHECKS():
    import json
    from datetime import datetime

    def as_text(value):
        if value is None:
            return ""
        return str(value).strip()

    def is_true(value):
        if isinstance(value, bool):
            return value
        return as_text(value).lower() == "true"

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value)
        for wrapper in ["data", "response", "result", "apiResponse", "_response_data"]:
            if isinstance(value, dict) and wrapper in value and "accessPolicies" not in value and "signOnPolicies" not in value:
                value = value[wrapper]
        return value

    def rule_list(item):
        if isinstance(item, dict):
            for wrapper in ["apiResponse", "response", "result"]:
                if wrapper in item:
                    return rule_list(item[wrapper])
            return None
        if isinstance(item, list):
            return [r for r in item if isinstance(r, dict)]
        return None

    def pair(policies, rules, label):
        if not isinstance(policies, list):
            return None, label + " policy list is missing"
        if not isinstance(rules, list) or len(rules) != len(policies):
            return None, label + " rule lists are missing or do not line up with the policies"
        out = []
        for index in range(len(policies)):
            policy = policies[index]
            if not isinstance(policy, dict):
                return None, label + " policy entry is not an object"
            found = rule_list(rules[index])
            if found is None:
                return None, label + " rules for policy '" + as_text(policy.get("name")) + "' are unreadable"
            out.append((policy, found))
        return out, None

    def is_active(obj):
        return as_text(obj.get("status")).upper() == "ACTIVE"

    def resource_type(policy):
        embedded = policy.get("_embedded")
        if isinstance(embedded, dict):
            return as_text(embedded.get("resourceType")).upper()
        return ""

    def error_in(data):
        if not isinstance(data, dict):
            return "Response is not an object with policy and rule lists"
        for k in ["errorCode", "errorSummary", "error", "errors", "errorMessage"]:
            if data.get(k):
                return "Okta returned an error: " + as_text(data.get(k))[:200]
        return None

    def evaluate(raw):
        data = parse(raw)
        state = {"error": None, "enforced": False, "enabled": False, "weak": [], "summary": "", "inputSummary": {}}
        problem = error_in(data)
        if problem is not None:
            state["error"] = problem
            return state
        access, access_problem = pair(data.get("accessPolicies"), data.get("accessRules"), "Authentication (ACCESS_POLICY)")
        signon, signon_problem = pair(data.get("signOnPolicies"), data.get("signOnRules"), "Global session (OKTA_SIGN_ON)")
        if access_problem is not None:
            state["error"] = access_problem
            return state

        app_policies = []
        other_policies = []
        for policy, rules in access or []:
            if not is_active(policy):
                continue
            kind = resource_type(policy)
            if kind in ["", "APP"]:
                app_policies.append((policy, rules))
            else:
                other_policies.append(as_text(policy.get("name")) + " (" + kind + ")")

        weak = []
        strong = 0
        judged_rules = 0
        if app_policies:
            engine = "Identity Engine"
            for policy, rules in app_policies:
                active_rules = [r for r in rules if is_active(r)]
                if not active_rules:
                    state["error"] = "Authentication policy '" + as_text(policy.get("name")) + "' has no active rules"
                    return state
                for rule in active_rules:
                    actions = rule.get("actions") if isinstance(rule.get("actions"), dict) else {}
                    sign_on = actions.get("appSignOn") if isinstance(actions.get("appSignOn"), dict) else {}
                    if as_text(sign_on.get("access")).upper() != "ALLOW":
                        continue
                    judged_rules = judged_rules + 1
                    method = sign_on.get("verificationMethod") if isinstance(sign_on.get("verificationMethod"), dict) else {}
                    method_type = as_text(method.get("type")).upper()
                    mode = as_text(method.get("factorMode")).upper()
                    where = as_text(policy.get("name")) + " / " + as_text(rule.get("name"))
                    if method_type == "ASSURANCE" and mode == "2FA":
                        strong = strong + 1
                    elif method_type == "ASSURANCE":
                        weak.append(where + " (factorMode " + (mode or "missing") + ")")
                    else:
                        weak.append(where + " (verification method " + (method_type or "missing") + " not evaluated)")
        elif signon is not None:
            engine = "Classic Engine"
            active_policies = [(p, r) for (p, r) in signon if is_active(p)]
            if not active_policies:
                state["error"] = "No active global session policy was returned"
                return state
            for policy, rules in active_policies:
                active_rules = [r for r in rules if is_active(r)]
                if not active_rules:
                    state["error"] = "Global session policy '" + as_text(policy.get("name")) + "' has no active rules"
                    return state
                for rule in active_rules:
                    actions = rule.get("actions") if isinstance(rule.get("actions"), dict) else {}
                    sign_on = actions.get("signon") if isinstance(actions.get("signon"), dict) else {}
                    if as_text(sign_on.get("access")).upper() != "ALLOW":
                        continue
                    judged_rules = judged_rules + 1
                    where = as_text(policy.get("name")) + " / " + as_text(rule.get("name"))
                    if is_true(sign_on.get("requireFactor")):
                        strong = strong + 1
                    else:
                        weak.append(where + " (requireFactor false)")
        else:
            state["error"] = "No active app authentication policy, and " + (signon_problem or "no global session policy")
            return state

        state["weak"] = weak
        state["enabled"] = strong > 0
        state["enforced"] = judged_rules > 0 and not weak
        state["summary"] = (engine + ": " + str(strong) + " of " + str(judged_rules) + " allowing sign-on rules require two factors across "
                            + str(len(app_policies) if app_policies else len(signon or [])) + " policies")
        state["inputSummary"] = {
            "engine": engine,
            "appPoliciesJudged": [as_text(p.get("name")) for (p, r) in app_policies],
            "policiesNotJudged": other_policies,
            "allowRules": judged_rules,
            "twoFactorRules": strong,
            "singleFactorRules": len(weak),
        }
        return state

    def respond(result, passes, fails, summary, errors):
        value = all(result.values())
        return {
            "transformedResponse": result,
            "additionalInfo": {
                "dataCollection": {"status": "success", "errors": []},
                "validation": {"status": "success" if not errors else "error", "errors": [], "warnings": []},
                "transformation": {"status": "error" if errors else "success", "errors": errors, "inputSummary": summary},
                "evaluation": {"passReasons": passes, "failReasons": fails, "recommendations": [] if value else
                               ["Require two factors (factorMode 2FA) on every rule that allows access in every Okta authentication policy"],
                               "additionalFindings": []},
                "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                             "transformationId": "isMFAEnforcedForUsers", "vendor": "Okta", "category": "Identity"},
            },
        }

    return {"evaluate": evaluate, "respond": respond}


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
