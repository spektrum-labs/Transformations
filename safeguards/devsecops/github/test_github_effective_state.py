"""GitHub AppSec checks read per-repository effective state, on the documented shapes of
GET /orgs/{org}/repos (security_and_analysis), the GraphQL organization.repositories
connection (hasVulnerabilityAlertsEnabled) and the org alert lists. Synthetic bodies
only: real org payloads are not committed to this repository."""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location("gh_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def repo(name, private=True, archived=False, **statuses):
    sa = {k: {"status": v} for k, v in statuses.items()}
    return {"full_name": "org/" + name, "private": private, "archived": archived, "disabled": False,
            "visibility": "private" if private else "public", "security_and_analysis": sa}


def gql(*flags, total=None):
    nodes = [{"nameWithOwner": "org/r%d" % i, "isArchived": False, "isDisabled": False,
              "hasVulnerabilityAlertsEnabled": f} for i, f in enumerate(flags)]
    return {"data": {"organization": {"repositories": {
        "totalCount": len(nodes) if total is None else total,
        "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": nodes}}}}


def alert(state="open"):
    return {"number": 1, "state": state, "secret_type": "aws_secret_access_key",
            "repository": {"full_name": "org/r0"}}


SPLIT = dict(code_security="enabled", secret_scanning="enabled")

CASES = [
    # (module, key, passing body, expected, failing flip, expected)
    ("isAdvancedSecurityEnabled", "isAdvancedSecurityEnabled",
     [repo("a", **SPLIT), repo("b", advanced_security="enabled"), repo("pub", private=False)], True,
     [repo("a", code_security="enabled", secret_scanning="disabled"), repo("b", advanced_security="enabled")], False),
    ("isDependabotAlertsEnabled", "isDependabotAlertsEnabled", gql(True, True), True, gql(True, False), False),
    ("isDependabotAlertsEnabled", "isDependabotAlertsEnabled", gql(True, True), True, gql(True, True, total=150), None),
    ("openSecretScanningAlertsCount", "openSecretScanningAlertsCount", [alert("resolved")], 0, [alert(), alert()], 2),
    # The definition pages to completion, so 200 (an exact multiple of 100) is the full count.
    ("openSecretScanningAlertsCount", "openSecretScanningAlertsCount", [], 0, [alert()] * 200, 200),
    # At the paginator cap open alerts are a lower bound that already fails "zero open".
    ("openSecretScanningAlertsCount", "openSecretScanningAlertsCount", [], 0, [alert()] * 5000, 5000),
    # At the cap with nothing open, zero cannot be proven: withhold.
    ("openSecretScanningAlertsCount", "openSecretScanningAlertsCount", [alert("resolved")] * 100, 0,
     [alert("resolved")] * 5000, None),
    ("openCriticalDependabotAlertsCount", "openCriticalDependabotAlertsCount", [], 0,
     {"message": "Not Found", "documentation_url": "https://docs.github.com/rest"}, None),
]


@pytest.mark.parametrize("module,key,good,good_exp,bad,bad_exp", CASES)
def test_pass_and_flip(module, key, good, good_exp, bad, bad_exp):
    t = load(module).transform
    assert t(good)["transformedResponse"][key] == good_exp
    assert t(bad)["transformedResponse"][key] == bad_exp


BAD_BODIES = [{}, None, "{}", {"message": "Not Found"}, {"data": None, "errors": [{"message": "forbidden"}]}]


BOOLEAN_MODULES = ["isAdvancedSecurityEnabled", "isDependabotAlertsEnabled", "isSecretScanningPushProtectionEnabled"]


def collection_status(out):
    return out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("module", BOOLEAN_MODULES)
@pytest.mark.parametrize("body", BAD_BODIES)
def test_booleans_unreadable_is_not_evaluated(module, body):
    # A refused, empty or unrecognised body is a read nobody completed, not a failed control:
    # the criterion is None and the data collection status is "error", which reads Not evaluated.
    out = load(module).transform(body)
    assert out["transformedResponse"][module] is None
    assert collection_status(out) == "error"


@pytest.mark.parametrize("module", ["openSecretScanningAlertsCount", "openCriticalDependabotAlertsCount"])
@pytest.mark.parametrize("body", BAD_BODIES)
def test_counts_withhold_on_non_list(module, body):
    assert load(module).transform(body)["transformedResponse"][module] is None


def drilled(body):
    """What Token-Service hands a legacy-format transform: the GraphQL "data" wrapper drilled away."""
    return body["data"]


def test_dependabot_reads_the_drilled_shape_token_service_sends():
    t = load("isDependabotAlertsEnabled").transform
    assert t(drilled(gql(True, True)))["transformedResponse"]["isDependabotAlertsEnabled"] is True
    assert t(drilled(gql(True, False)))["transformedResponse"]["isDependabotAlertsEnabled"] is False
    assert t(drilled(gql(True, True, total=150)))["transformedResponse"]["isDependabotAlertsEnabled"] is None
    assert t({"organization": None})["transformedResponse"]["isDependabotAlertsEnabled"] is None


def test_truncated_secret_count_is_flagged_as_lower_bound():
    tr = load("openSecretScanningAlertsCount").transform([alert()] * 5000)["transformedResponse"]
    assert tr["countIsLowerBound"] is True
    for n in (3, 200, 4900):
        tr = load("openSecretScanningAlertsCount").transform([alert()] * n)["transformedResponse"]
        assert tr["countIsLowerBound"] is False


def pp_repo(name, status=None, private=True, archived=False):
    sa = {} if status is None else {"secret_scanning_push_protection": {"status": status}}
    return {"full_name": "org/" + name, "private": private, "archived": archived, "disabled": False,
            "visibility": "private" if private else "public", "security_and_analysis": sa}


def value(module, body):
    out = load(module).transform(body)
    return out["transformedResponse"][module], collection_status(out)


def test_advanced_security_unreadable_reads_not_evaluated_but_read_failures_still_fail():
    m = "isAdvancedSecurityEnabled"
    assert value(m, [repo("a", **SPLIT)]) == (True, "success")
    # An empty organization list, or only public repositories (an unapproved token sees those only).
    assert value(m, []) == (None, "error")
    assert value(m, [repo("pub", private=False)]) == (None, "error")
    # The security_and_analysis block is missing: the token cannot see it.
    blind = {"full_name": "org/blind", "private": True, "archived": False, "disabled": False,
             "visibility": "private"}
    assert value(m, [blind]) == (None, "error")
    assert value(m, [repo("a", **SPLIT), blind]) == (None, "error")
    # A repository that was read and is not covered fails, whatever else could not be read.
    assert value(m, [repo("a", code_security="disabled", secret_scanning="disabled"), blind]) == (False, "success")
    assert value(m, [repo("a", code_security="enabled", secret_scanning="disabled")]) == (False, "success")


def test_push_protection_unreadable_reads_not_evaluated_but_read_failures_still_fail():
    m = "isSecretScanningPushProtectionEnabled"
    assert value(m, [pp_repo("a", "enabled"), pp_repo("b", "enabled")]) == (True, "success")
    assert value(m, [pp_repo("a", "enabled"), pp_repo("old", "disabled", archived=True)]) == (True, "success")
    assert value(m, []) == (None, "error")
    assert value(m, [pp_repo("old", "enabled", archived=True)]) == (None, "error")
    # No repository reports the field, or only some do and none is off.
    assert value(m, [pp_repo("a"), pp_repo("b")]) == (None, "error")
    assert value(m, [pp_repo("a", "enabled"), pp_repo("b")]) == (None, "error")
    # A repository that was read with push protection off fails the check.
    assert value(m, [pp_repo("a", "disabled")]) == (False, "success")
    assert value(m, [pp_repo("a", "disabled"), pp_repo("b")]) == (False, "success")


def test_dependabot_alerts_unreported_flag_reads_not_evaluated_but_read_off_still_fails():
    m = "isDependabotAlertsEnabled"
    assert value(m, gql(True, True)) == (True, "success")
    assert value(m, gql(True, None)) == (None, "error")
    assert value(m, gql()) == (None, "error")
    assert value(m, gql(True, False)) == (False, "success")
    assert value(m, gql(None, False)) == (False, "success")


def test_dependabot_repository_read_with_alerts_off_still_fails_beside_a_short_read():
    m = "isDependabotAlertsEnabled"
    # 150 repositories, 2 read, one with alerts off: a known gap is a fail, not hidden as Not evaluated.
    assert value(m, gql(False, True, total=150)) == (False, "success")
    trunc = gql(True, False)
    trunc["data"]["organization"]["repositories"]["pageInfo"]["truncated"] = True
    out = load(m).transform(trunc)
    assert (out["transformedResponse"][m], collection_status(out)) == (False, "success")
    assert any("Not every repository could be read" in r for r in out["additionalInfo"]["evaluation"]["failReasons"])
    errs = gql(False)
    errs["errors"] = [{"message": "partial"}]
    assert value(m, errs) == (False, "success")
    # A short read with every repository read on is still Not evaluated.
    assert value(m, gql(True, True, total=150)) == (None, "error")


def _empty_connection(**extra):
    """The shape the paginator leaves when the organization could not be read: a nodes list and nothing else."""
    return {"organization": {"repositories": {"nodes": [], **extra}}}


def test_dependabot_withholds_when_the_organization_could_not_be_read():
    """No nodes and no totalCount: the connection never arrived (wrong organization name, or a token that cannot
    see it). That is a read failure, so the criterion is not evaluated; it must not be scored as a finding."""
    out = load("isDependabotAlertsEnabled").transform(_empty_connection())
    assert out["transformedResponse"]["isDependabotAlertsEnabled"] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert "organization name may be wrong" in collection["errors"][0]


def test_dependabot_organization_with_no_repositories_is_not_evaluated():
    """totalCount 0 arrived, so the organization was read, but no active repository reports a Dependabot state:
    there is nothing to judge, so the criterion is Not evaluated (never a pass), like an empty list elsewhere."""
    out = load("isDependabotAlertsEnabled").transform(_empty_connection(totalCount=0))
    assert out["transformedResponse"]["isDependabotAlertsEnabled"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_dependabot_pass_is_unchanged_by_the_empty_read_rule():
    out = load("isDependabotAlertsEnabled").transform(gql(True, True))
    assert out["transformedResponse"]["isDependabotAlertsEnabled"] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
