import json
from datetime import datetime

KEY = "isPullRequestApprovalRequired"


def extract_input(input_data):
    if isinstance(input_data, (str, bytes)):
        try:
            input_data = json.loads(input_data)
        except Exception:
            input_data = {}
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def is_step_error(value):
    return isinstance(value, dict) and value.get("stepError") is True


def describe_step_error(value):
    if not isinstance(value, dict):
        return "no data"
    parts = []
    status = value.get("statusCode")
    if isinstance(status, int) and not isinstance(status, bool):
        parts.append("HTTP " + str(status))
    summary = value.get("errorSummary")
    if isinstance(summary, str) and summary:
        parts.append(summary[:120])
    return ", ".join(parts) if parts else "an error"


def item_status(value):
    """HTTP status of a per-repository item error record, or None."""
    if isinstance(value, dict) and value.get("error") is True:
        status = value.get("statusCode")
        if isinstance(status, int) and not isinstance(status, bool):
            return status
        return 0
    return None


def to_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def flag_true(stats, key, field):
    if not isinstance(stats, dict):
        return False
    entry = stats.get(key)
    return isinstance(entry, dict) and entry.get(field) is True


def repo_label(r):
    name = r.get("full_name")
    if isinstance(name, str) and name:
        return name
    owner = r.get("owner") if isinstance(r.get("owner"), dict) else {}
    login = owner.get("login") if isinstance(owner.get("login"), str) else "unknown"
    return login + "/" + str(r.get("name") or "unknown")


def ruleset_candidates(rules, inactive_ids):
    """Approval requirements from the effective rules list: (count, last_push, source, id).

    GET /repos/{owner}/{repo}/rules/branches/{branch} returns only rules from rulesets in
    "active" enforcement (GitHub: rules in rulesets with "evaluate" or "disabled" enforcement
    are not returned). As a guard, a rule that carries its own non-active "enforcement", or
    whose organization ruleset detail says it is not active, is skipped too.
    """
    out = []
    for rule in rules:
        if not isinstance(rule, dict) or rule.get("type") != "pull_request":
            continue
        enforcement = rule.get("enforcement")
        if isinstance(enforcement, str) and enforcement != "active":
            continue
        source_type = rule.get("ruleset_source_type")
        if source_type == "Organization" and rule.get("ruleset_id") in inactive_ids:
            continue
        params = rule.get("parameters") if isinstance(rule.get("parameters"), dict) else {}
        source = "organization ruleset" if source_type == "Organization" else (
            "repository ruleset" if source_type == "Repository" else "ruleset")
        out.append(layer(params, source, rule.get("ruleset_id")))
    return out


def layer(params, source, ruleset_id):
    """One layer's approval requirement. ``missing`` names a field the layer did not give as the
    documented type (an integer count, a boolean last-push flag)."""
    count = to_int(params.get("required_approving_review_count"))
    last_push = params.get("require_last_push_approval")
    missing = []
    if count is None:
        missing.append("required_approving_review_count")
    if not isinstance(last_push, bool):
        missing.append("require_last_push_approval")
    return {"count": count, "lastPush": last_push is True, "source": source,
            "rulesetId": ruleset_id, "missing": missing}


def classic_candidate(protection):
    reviews = protection.get("required_pull_request_reviews")
    if not isinstance(reviews, dict):
        return None
    return layer(reviews, "classic branch protection", None)


def classic_bypass_notes(protection, label):
    notes = []
    admins = protection.get("enforce_admins")
    if isinstance(admins, dict) and admins.get("enabled") is False:
        notes.append(label + ": classic protection has enforce_admins off, so repository admins can bypass it.")
    reviews = protection.get("required_pull_request_reviews")
    allowances = reviews.get("bypass_pull_request_allowances") if isinstance(reviews, dict) else None
    if isinstance(allowances, dict):
        for kind in ("users", "teams", "apps"):
            members = allowances.get(kind)
            if isinstance(members, list) and members:
                notes.append(label + ": classic protection lets " + str(len(members)) + " " + kind
                             + " bypass the pull request requirement.")
    return notes


def ruleset_bypass_index(details):
    """ruleset id -> list of bypass actor types, or None when the list was not returned."""
    index = {}
    if not isinstance(details, list):
        return index
    for d in details:
        if not isinstance(d, dict) or d.get("error") is True:
            continue
        rid = d.get("id")
        actors = d.get("bypass_actors")
        if not isinstance(actors, list):
            index[rid] = None
            continue
        kinds = []
        for a in actors:
            if isinstance(a, dict):
                kind = str(a.get("actor_type") or "unknown")
                mode = a.get("bypass_mode")
                if isinstance(mode, str) and mode:
                    kind = kind + " (" + mode + ")"
                kinds.append(kind)
        index[rid] = kinds
    return index


def inactive_org_ruleset_ids(details):
    ids = {}
    if not isinstance(details, list):
        return ids
    for d in details:
        if isinstance(d, dict) and d.get("error") is not True:
            enforcement = d.get("enforcement")
            if isinstance(enforcement, str) and enforcement != "active":
                ids[d.get("id")] = True
    return ids


def is_branch_not_found(item):
    """Classic protection's 404 "Branch not found": the default branch does not exist (a
    repository with no commits)."""
    if not isinstance(item, dict):
        return False
    envelope = item.get("vendorErrorAsResponse")
    return isinstance(envelope, dict) and envelope.get("status") == 404 \
        and envelope.get("bodyContains") == "Branch not found"


def judge_repo(rules_item, protection_item, inactive_ids):
    """One repository, aggregated across every active layer that targets the default branch.

    GitHub applies all of them and the strictest value of each parameter, so the repository
    passes when the highest required approving count across the layers read is >= 1 AND any
    layer read requires approval of the most recent push. Layers that were read can pass on
    their own even when another layer is unreadable; otherwise an unreadable layer means the
    repository is not evaluated.

    Returns ("pass", layers, contributing) | ("fail", missing, []) | ("unreadable", why, []).
    """
    unreadable = []
    candidates = []

    rules_status = item_status(rules_item)
    if isinstance(rules_item, list):
        candidates.extend(ruleset_candidates(rules_item, inactive_ids))
    elif rules_status is not None:
        unreadable.append("branch rules HTTP " + str(rules_status))
    else:
        unreadable.append("branch rules not returned")

    protection_status = item_status(protection_item)
    if is_branch_not_found(protection_item):
        return "empty", "default branch not found", []
    if isinstance(protection_item, dict) and isinstance(protection_item.get("vendorErrorAsResponse"), dict):
        envelope = protection_item.get("vendorErrorAsResponse")
        if envelope.get("status") != 404:
            unreadable.append("classic protection HTTP " + str(envelope.get("status")))
        # A 404 "Branch not protected" is an answer: no classic protection.
    elif protection_status is not None:
        unreadable.append("classic protection HTTP " + str(protection_status))
    elif isinstance(protection_item, dict) and protection_item:
        cand = classic_candidate(protection_item)
        if cand is not None:
            candidates.append(cand)
    else:
        unreadable.append("classic protection not returned")

    counts = [c["count"] for c in candidates if c["count"] is not None]
    max_count = max(counts) if counts else None
    count_layers = [c for c in candidates if max_count is not None and max_count >= 1 and c["count"] == max_count]
    push_layers = [c for c in candidates if c["lastPush"]]

    if count_layers and push_layers:
        count_from = count_layers[0]["source"]
        push_from = push_layers[0]["source"]
        if count_from == push_from:
            detail = count_from
        else:
            detail = str(max_count) + " required approval(s) from " + count_from + ", last-push approval from " + push_from
        return "pass", detail, count_layers + push_layers
    if unreadable:
        return "unreadable", ", ".join(unreadable), []
    incomplete = []
    for c in candidates:
        for field in c.get("missing") or []:
            incomplete.append(c["source"] + " has no " + field)
    if incomplete:
        # A layer that does not state its count or last-push setting cannot prove a failure.
        return "unreadable", "; ".join(incomplete), []

    if not candidates:
        missing = "no approval rule"
    elif max_count is None or max_count < 1:
        missing = "0 required approvals"
        if not push_layers:
            missing = missing + " and last-push approval off"
    else:
        missing = "last-push approval off"
    return "fail", missing, []


def transform(input):
    """Pull requests on every active repository's default branch need an approval from someone
    other than the last pusher.

    GitHub always blocks an author approving their own pull request, so that is not a setting.
    What an organization controls is whether the default branch requires at least one approving
    review AND "require approval of the most recent reviewable push", so whoever pushed last
    cannot be the approver. The layers are organization rulesets and repository rulesets
    (GET /repos/{owner}/{repo}/rules/branches/{branch}, which returns only rules from rulesets in
    active enforcement) and classic branch protection (GET .../branches/{branch}/protection,
    required_pull_request_reviews). GitHub applies every active layer and the strictest value of
    each parameter, so a repository passes when the highest required approving count across the
    layers read is >= 1 AND any layer read requires approval of the most recent push. A ruleset
    in evaluate or disabled enforcement does not count.

    Input, from the Integration-Service workflow of the same name: repositories (the org list),
    branchRules and branchProtection (one slot per repository, same order; a failed read is
    {"error": true, "statusCode": N}), a 404 "Branch not protected" as
    {"vendorErrorAsResponse": {"status": 404}}, list failures as {"stepError": true}, and
    orgRulesetDetails for bypass actors.

    Results:
      * True: every active (not archived, not disabled) repository read passes, and every
        repository was read.
      * False: at least one repository was READ and has no qualifying rule; the reasons name each
        and what is missing (no approval rule, 0 required approvals, last-push approval off).
      * None (Not evaluated, with a data collection error): the rules could not be read, that is a
        refused or missing list, no active repository, a repository whose reads returned 403/404
        without a passing rule, a cut-off read, a repository without a default branch, or a layer
        that does not state its count or last-push setting (unless the other layers pass alone).
    Empty repositories (classic protection answers 404 "Branch not found") are skipped and counted.
    Admin bypass (enforce_admins off, bypass allowances, ruleset bypass actors) is reported and
    never fails the check; whether it should is an open decision.
    """
    data, validation = extract_input(input)
    body = data if isinstance(data, dict) else {}

    api_errors = []
    findings = []

    repos = body.get("repositories")
    rules = body.get("branchRules")
    protection = body.get("branchProtection")

    if is_step_error(repos):
        api_errors.append("The repository list could not be read (" + describe_step_error(repos) + ").")
        repos = []
    elif not isinstance(repos, list):
        api_errors.append("The response has no repository list.")
        repos = []
    elif not repos:
        api_errors.append("The repository list was empty, so no default branch could be read.")

    if repos and is_step_error(rules):
        api_errors.append("Branch rules could not be read (" + describe_step_error(rules) + ").")
    if repos and is_step_error(protection):
        api_errors.append("Classic branch protection could not be read (" + describe_step_error(protection) + ").")
    if not isinstance(rules, list):
        rules = []
    if not isinstance(protection, list):
        protection = []

    if flag_true(body.get("paginationStats"), "repositories", "paginationTruncated") or body.get("paginationTruncated") is True:
        api_errors.append("The repository list stopped at its page limit, so not every repository was read.")

    excluded = 0
    empty = 0
    passing = []
    failing = []
    unreadable = []
    not_read = []
    org_rulesets_used = {}
    inactive_ids = inactive_org_ruleset_ids(body.get("orgRulesetDetails"))
    for index, r in enumerate(repos):
        if not isinstance(r, dict):
            continue
        if r.get("archived") is True or r.get("disabled") is True:
            excluded += 1
            continue
        label = repo_label(r)
        branch = r.get("default_branch")
        if not isinstance(branch, str) or not branch:
            unreadable.append(label + " (no default branch)")
            continue
        if index >= len(rules) and index >= len(protection):
            not_read.append(label)
            continue
        rules_item = rules[index] if index < len(rules) else None
        protection_item = protection[index] if index < len(protection) else None
        verdict, detail, layers = judge_repo(rules_item, protection_item, inactive_ids)
        if verdict == "pass":
            passing.append(label + " (" + detail + ")")
            repo_ruleset_noted = False
            for layer in layers:
                if layer["source"] == "organization ruleset":
                    org_rulesets_used[layer.get("rulesetId")] = True
                elif layer["source"] == "repository ruleset" and not repo_ruleset_noted:
                    repo_ruleset_noted = True
                    findings.append(label + ": a passing layer is a repository ruleset; its bypass list was not read.")
        elif verdict == "empty":
            empty += 1
            continue
        elif verdict == "fail":
            failing.append(label + ": " + detail)
        else:
            unreadable.append(label + " (" + detail + ")")
        if isinstance(protection_item, dict) and item_status(protection_item) is None \
                and "vendorErrorAsResponse" not in protection_item:
            findings.extend(classic_bypass_notes(protection_item, label))

    active = len(passing) + len(failing) + len(unreadable) + len(not_read)
    if repos and active == 0 and not api_errors:
        api_errors.append("No active (not archived, not disabled) repository with a default branch was returned.")
    if not_read:
        api_errors.append(str(len(not_read)) + " active repositories were beyond the per-repository read limit and not read (e.g. "
                          + ", ".join(not_read[:5]) + ").")
    if unreadable and not failing:
        api_errors.append("The approval rules of " + str(len(unreadable)) + " active repositories could not be read (e.g. "
                          + "; ".join(unreadable[:5]) + ").")

    # Bypass on the organization rulesets that made a repository pass.
    if org_rulesets_used:
        details = body.get("orgRulesetDetails")
        if is_step_error(details) or is_step_error(body.get("orgRulesets")):
            findings.append("Organization rulesets could not be read ("
                            + describe_step_error(details if is_step_error(details) else body.get("orgRulesets"))
                            + "), so their bypass actors are unknown.")
        else:
            index = ruleset_bypass_index(details)
            for rid in org_rulesets_used:
                if rid not in index:
                    findings.append("Organization ruleset " + str(rid) + " was not returned by the ruleset read, so its bypass actors are unknown.")
                elif index[rid] is None:
                    findings.append("Organization ruleset " + str(rid) + " did not return its bypass list (it is returned only to a token with write access to the ruleset).")
                elif index[rid]:
                    findings.append("Organization ruleset " + str(rid) + " lets these bypass it: " + ", ".join(index[rid][:10]) + ".")

    if failing:
        result = False
    elif api_errors:
        result = None
    else:
        result = True

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if excluded:
        findings.append(str(excluded) + " archived or disabled repositories were excluded.")
    if empty:
        findings.append(str(empty) + " empty repositories (default branch not found) were skipped.")
    if result is True:
        pass_reasons.append("All " + str(len(passing)) + " active repositories require at least one approving review and approval of the most recent push on their default branch, across their active rulesets and classic protection (e.g. "
                            + "; ".join(passing[:5]) + ").")
    elif result is False:
        fail_reasons.append(str(len(failing)) + " of " + str(active) + " active repositories do not require an approval from someone other than the last pusher on their default branch: "
                            + "; ".join(failing[:20]) + ".")
        if unreadable:
            fail_reasons.append(str(len(unreadable)) + " more could not be read (e.g. " + "; ".join(unreadable[:5]) + ").")
        recommendations.append("Add a branch ruleset (organization-wide is simplest) on the default branch with 'Require a pull request before merging', at least 1 required approval, and 'Require approval of the most recent reviewable push'.")
    else:
        fail_reasons.append("Pull request approval rules could not be read for every active repository: " + " ".join(api_errors))
        recommendations.append("Use a token owned by an organization owner with access to all repositories: repository Administration: read and Metadata: read, and organization Administration: read (classic tokens: repo and read:org). Have an owner approve it if the organization requires approval.")

    result_obj = {KEY: result}
    return create_response(
        result=result_obj,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=findings,
        input_summary={
            "repositoriesRead": len(repos),
            "activeRepositories": active,
            "excludedArchivedOrDisabled": excluded,
            "skippedEmpty": empty,
            "passing": len(passing),
            "failingRepos": failing[:50],
            "unreadableRepos": unreadable[:50],
            "notReadRepos": not_read[:50],
        },
        api_errors=api_errors if result is None else None,
        metadata={
            "transformationId": KEY,
            "vendor": "GitHub",
            "category": "devsecops",
        },
    )
