"""isPullRequestApprovalRequired: every active repository's default branch requires at least one
approving review AND approval of the most recent reviewable push, from an organization ruleset,
a repository ruleset or classic branch protection.

Bodies follow the shape the Integration-Service workflow isPullRequestApprovalRequired produces
(GitHub definition): repositories (GET /orgs/{org}/repos), branchRules and branchProtection (one
slot per repository, same order), orgRulesets and orgRulesetDetails. A failed per-repository read
is an item error record {"error": true, "statusCode": N, "item": {...}}; a failed list read is a
step marker {"stepError": true, ...}; classic protection's 404 "Branch not protected" arrives as
{"vendorErrorAsResponse": {"status": 404, ...}}. Synthetic data only."""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
KEY = "isPullRequestApprovalRequired"


def load():
    spec = importlib.util.spec_from_file_location("gh_" + KEY, HERE / (KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(body):
    return load().transform(body)


def value(out):
    return out["transformedResponse"][KEY]


def reasons(out):
    ev = out["additionalInfo"]["evaluation"]
    return " ".join(ev["passReasons"] + ev["failReasons"] + ev["additionalFindings"])


def repo(name, archived=False, disabled=False):
    return {"name": name, "full_name": "example-org/" + name, "owner": {"login": "example-org"},
            "default_branch": "main", "archived": archived, "disabled": disabled}


def pr_rule(count=1, last_push=True, source="Organization", ruleset_id=7):
    return {"type": "pull_request", "ruleset_source_type": source, "ruleset_source": "example-org",
            "ruleset_id": ruleset_id,
            "parameters": {"required_approving_review_count": count,
                           "require_last_push_approval": last_push,
                           "dismiss_stale_reviews_on_push": False,
                           "require_code_owner_review": False,
                           "required_review_thread_resolution": False}}


def classic(count=1, last_push=True, enforce_admins=True):
    return {"url": "https://api.github.example/repos/example-org/x/branches/main/protection",
            "required_pull_request_reviews": {"required_approving_review_count": count,
                                              "require_last_push_approval": last_push,
                                              "dismiss_stale_reviews": False,
                                              "require_code_owner_reviews": False},
            "enforce_admins": {"enabled": enforce_admins}}


NOT_PROTECTED = {"vendorErrorAsResponse": {"status": 404, "bodyContains": "Branch not protected",
                                           "body": {"message": "Branch not protected"}}}


def item_error(status, name):
    return {"error": True, "statusCode": status, "errorType": "vendorError",
            "item": {"repoOwner": "example-org", "repoName": name, "branch": "main"}}


def body(repos, rules, protection, details=None, rulesets=None):
    return {
        "repositories": repos,
        "branchRules": rules,
        "branchProtection": protection,
        "orgRulesets": rulesets if rulesets is not None else [{"id": 7, "name": "default"}],
        "orgRulesetDetails": details if details is not None else [
            {"id": 7, "enforcement": "active", "bypass_actors": []}],
        "paginationStats": {"repositories": {"paginationTruncated": False}},
        "iterateStats": {
            "branchRules": {"itemsTotal": len(repos) if isinstance(repos, list) else 0,
                            "itemsProcessed": len(rules) if isinstance(rules, list) else 0,
                            "itemErrors": 0, "iterateTruncated": False},
        },
    }


# ----------------------------------------------------------------------------- True


def test_classic_protection_passes():
    out = run(body([repo("api")], [[]], [classic()]))
    assert value(out) is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_org_ruleset_passes():
    out = run(body([repo("api")], [[pr_rule()]], [NOT_PROTECTED]))
    assert value(out) is True
    assert "organization ruleset" in reasons(out)


def test_repo_ruleset_passes():
    out = run(body([repo("api")], [[pr_rule(source="Repository", ruleset_id=9)]], [NOT_PROTECTED]))
    assert value(out) is True
    assert "repository ruleset" in reasons(out)


def test_a_passing_ruleset_needs_no_classic_protection_read():
    """Classic protection is admin-only; a 403 there does not hide a ruleset that passes."""
    out = run(body([repo("api")], [[pr_rule()]], [item_error(403, "api")]))
    assert value(out) is True


def test_unwrapped_from_an_api_response_envelope():
    out = run({"apiResponse": body([repo("api")], [[pr_rule()]], [NOT_PROTECTED])})
    assert value(out) is True


# ----------------------------------------------------------------------------- False


def test_last_push_approval_off_fails_and_says_so():
    out = run(body([repo("api"), repo("web")], [[pr_rule()], [pr_rule(last_push=False)]],
                   [NOT_PROTECTED, NOT_PROTECTED]))
    assert value(out) is False
    text = reasons(out)
    assert "example-org/web" in text and "last-push approval off" in text
    assert "example-org/api" not in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_zero_required_approvals_fails():
    out = run(body([repo("api")], [[]], [classic(count=0)]))
    assert value(out) is False
    assert "0 required approvals" in reasons(out)


def test_no_approval_rule_fails():
    out = run(body([repo("api")], [[]], [NOT_PROTECTED]))
    assert value(out) is False
    assert "no approval rule" in reasons(out)


def test_a_failing_repository_fails_even_when_another_is_unreadable():
    out = run(body([repo("api"), repo("web")], [[], item_error(403, "web")],
                   [NOT_PROTECTED, item_error(403, "web")]))
    assert value(out) is False
    assert "example-org/web" in reasons(out)


# ----------------------------------------------------------------------------- None


def test_403_on_the_reads_is_not_evaluated_never_false():
    out = run(body([repo("api")], [item_error(403, "api")], [item_error(403, "api")]))
    assert value(out) is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "403" in reasons(out) and "example-org/api" in reasons(out)


def test_a_plain_404_on_classic_protection_is_not_evaluated():
    out = run(body([repo("api")], [[]], [item_error(404, "api")]))
    assert value(out) is None
    assert "404" in reasons(out)


def test_unreadable_repository_list_is_not_evaluated():
    marker = {"stepError": True, "statusCode": 403, "errorSummary": "Resource not accessible"}
    skipped = {"stepError": True, "skipped": True, "errorSummary": "not called"}
    out = run(body(marker, skipped, skipped))
    assert value(out) is None
    assert "repository list" in reasons(out) and "403" in reasons(out)


def test_no_repositories_is_not_evaluated():
    out = run(body([], [], []))
    assert value(out) is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_empty_or_missing_data_is_not_evaluated():
    for b in ({}, [], "", {"repositories": [repo("api")]}, {"message": "Bad credentials"}):
        out = run(b)
        assert value(out) is None, b
        assert out["additionalInfo"]["dataCollection"]["status"] == "error", b


def test_a_cut_off_repository_read_cannot_pass():
    b = body([repo("api")], [[pr_rule()]], [NOT_PROTECTED])
    b["paginationStats"]["repositories"]["paginationTruncated"] = True
    out = run(b)
    assert value(out) is None
    assert "not every repository" in reasons(out)


def test_repositories_beyond_the_fan_out_cap_are_not_read():
    b = body([repo("api"), repo("web")], [[pr_rule()]], [NOT_PROTECTED])
    b["iterateStats"]["branchRules"]["iterateTruncated"] = True
    out = run(b)
    assert value(out) is None
    assert "example-org/web" in reasons(out)


# ----------------------------------------------------------------------------- scope


def test_archived_and_disabled_repositories_are_excluded_and_counted():
    out = run(body([repo("api"), repo("old", archived=True), repo("gone", disabled=True)],
                   [[pr_rule()], [], []], [NOT_PROTECTED, NOT_PROTECTED, NOT_PROTECTED]))
    assert value(out) is True
    assert "2 archived or disabled" in reasons(out)


def test_only_archived_repositories_is_not_evaluated():
    out = run(body([repo("old", archived=True)], [[]], [NOT_PROTECTED]))
    assert value(out) is None


# ----------------------------------------------------------------------------- bypass


def test_admin_bypass_is_reported_but_does_not_fail():
    out = run(body([repo("api")], [[]], [classic(enforce_admins=False)]))
    assert value(out) is True
    assert "enforce_admins" in reasons(out)


def test_ruleset_bypass_actors_are_reported_but_do_not_fail():
    details = [{"id": 7, "enforcement": "active",
                "bypass_actors": [{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"}]}]
    out = run(body([repo("api")], [[pr_rule()]], [NOT_PROTECTED], details=details))
    assert value(out) is True
    assert "OrganizationAdmin" in reasons(out)


def test_unreadable_org_rulesets_only_note_that_bypass_is_unknown():
    marker = {"stepError": True, "statusCode": 403, "errorSummary": "Resource not accessible"}
    out = run(body([repo("api")], [[pr_rule()]], [NOT_PROTECTED], details=marker, rulesets=marker))
    assert value(out) is True
    assert "bypass" in reasons(out)


def test_only_the_criteria_key_is_emitted():
    out = run(body([repo("api")], [[pr_rule()]], [NOT_PROTECTED]))
    assert list(out["transformedResponse"]) == [KEY]


# ----------------------------------------------------------------------------- layer aggregation
# GitHub applies every active layer (org rulesets, repo rulesets, classic protection) and the
# strictest value of each parameter: the repository passes when the max required count across
# its active layers is >= 1 and any active layer requires last-push approval.


def test_count_on_classic_and_last_push_on_org_ruleset_pass_together():
    out = run(body([repo("api")], [[pr_rule(count=0, last_push=True)]], [classic(count=2, last_push=False)]))
    assert value(out) is True
    text = reasons(out)
    assert "classic branch protection" in text and "organization ruleset" in text


def test_count_on_repo_ruleset_and_last_push_on_classic_pass_together():
    out = run(body([repo("api")], [[pr_rule(count=1, last_push=False, source="Repository", ruleset_id=9)]],
                   [classic(count=0, last_push=True)]))
    assert value(out) is True
    assert "repository ruleset" in reasons(out)


def test_count_zero_on_every_layer_still_fails():
    out = run(body([repo("api")], [[pr_rule(count=0, last_push=True)]], [classic(count=0, last_push=True)]))
    assert value(out) is False
    assert "0 required approvals" in reasons(out)


def test_last_push_on_without_any_required_count_still_fails():
    out = run(body([repo("api")], [[pr_rule(count=0, last_push=True, source="Repository", ruleset_id=9)]],
                   [NOT_PROTECTED]))
    assert value(out) is False
    assert "0 required approvals" in reasons(out)


def test_a_ruleset_in_evaluate_mode_does_not_count():
    details = [{"id": 7, "enforcement": "active", "bypass_actors": []},
               {"id": 8, "enforcement": "evaluate", "bypass_actors": []}]
    out = run(body([repo("api")], [[pr_rule(count=0, last_push=True, ruleset_id=8)]],
                   [classic(count=1, last_push=False)], details=details))
    assert value(out) is False
    assert "last-push approval off" in reasons(out)


def test_a_rule_marked_disabled_in_the_rules_body_does_not_count():
    rule = pr_rule(count=1, last_push=True, source="Repository", ruleset_id=9)
    rule["enforcement"] = "disabled"
    out = run(body([repo("api")], [[rule]], [NOT_PROTECTED]))
    assert value(out) is False
    assert "no approval rule" in reasons(out)


def test_read_layers_that_together_pass_are_enough_when_another_layer_is_unreadable():
    out = run(body([repo("api")], [[pr_rule(count=0, last_push=True), pr_rule(count=1, last_push=False, source="Repository", ruleset_id=9)]],
                   [item_error(403, "api")]))
    assert value(out) is True


def test_read_layers_that_do_not_pass_with_another_unreadable_are_not_evaluated():
    out = run(body([repo("api")], [[pr_rule(count=1, last_push=False)]], [item_error(403, "api")]))
    assert value(out) is None


# ----------------------------------------------------------------------------- missing fields
# A layer that does not say its count or its last-push setting cannot prove a failure: unless
# the layers that were read pass on their own, the repository is not evaluated, and the reason
# names the missing field.


def _without(rule_or_classic, field):
    params = rule_or_classic.get("parameters") or rule_or_classic.get("required_pull_request_reviews")
    params.pop(field)
    return rule_or_classic


def test_a_ruleset_missing_its_count_is_not_evaluated():
    out = run(body([repo("api")], [[_without(pr_rule(), "required_approving_review_count")]], [NOT_PROTECTED]))
    assert value(out) is None
    assert "required_approving_review_count" in reasons(out)


def test_a_missing_count_beside_a_layer_at_zero_is_not_evaluated():
    out = run(body([repo("api")], [[_without(pr_rule(), "required_approving_review_count")]],
                   [classic(count=0, last_push=False)]))
    assert value(out) is None
    assert "required_approving_review_count" in reasons(out)


def test_a_missing_last_push_with_nothing_else_passing_is_not_evaluated():
    out = run(body([repo("api")], [[_without(pr_rule(count=1), "require_last_push_approval")]], [NOT_PROTECTED]))
    assert value(out) is None
    assert "require_last_push_approval" in reasons(out)


def test_a_missing_count_beside_a_passing_layer_still_passes():
    out = run(body([repo("api")], [[_without(pr_rule(source="Repository", ruleset_id=9), "required_approving_review_count")]],
                   [classic(count=1, last_push=True)]))
    assert value(out) is True


def test_classic_protection_missing_its_count_is_not_evaluated():
    out = run(body([repo("api")], [[]], [_without(classic(), "required_approving_review_count")]))
    assert value(out) is None
    assert "required_approving_review_count" in reasons(out)


def test_a_non_integer_count_is_not_evaluated():
    rule = pr_rule()
    rule["parameters"]["required_approving_review_count"] = "1"
    out = run(body([repo("api")], [[rule]], [NOT_PROTECTED]))
    assert value(out) is None


# ----------------------------------------------------------------------------- empty repos, no default branch


BRANCH_NOT_FOUND = {"vendorErrorAsResponse": {"status": 404, "bodyContains": "Branch not found",
                                              "body": {"message": "Branch not found"}}}


def test_an_empty_repository_is_skipped_and_counted_not_none_for_everything():
    out = run(body([repo("api"), repo("empty")], [[pr_rule()], []], [NOT_PROTECTED, BRANCH_NOT_FOUND]))
    assert value(out) is True
    assert "1 empty repositories" in reasons(out)


def test_only_empty_repositories_is_not_evaluated():
    out = run(body([repo("empty")], [[]], [BRANCH_NOT_FOUND]))
    assert value(out) is None


def test_a_repository_without_a_default_branch_is_not_evaluated():
    r = repo("odd")
    r["default_branch"] = None
    refused = {"error": True, "statusCode": 422, "errorType": "vendorError", "item": None}
    out = run(body([repo("api"), r], [[pr_rule()], refused], [NOT_PROTECTED, refused]))
    assert value(out) is None
    assert "example-org/odd" in reasons(out) and "no default branch" in reasons(out)
