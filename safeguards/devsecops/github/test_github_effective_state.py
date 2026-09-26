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
    ("isDependabotAlertsEnabled", "isDependabotAlertsEnabled", gql(True, True), True, gql(True, True, total=150), False),
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


@pytest.mark.parametrize("module", ["isAdvancedSecurityEnabled", "isDependabotAlertsEnabled"])
@pytest.mark.parametrize("body", BAD_BODIES)
def test_booleans_fail_closed(module, body):
    assert load(module).transform(body)["transformedResponse"][module] is False


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
    assert t(drilled(gql(True, True, total=150)))["transformedResponse"]["isDependabotAlertsEnabled"] is False
    assert t({"organization": None})["transformedResponse"]["isDependabotAlertsEnabled"] is False


def test_truncated_secret_count_is_flagged_as_lower_bound():
    tr = load("openSecretScanningAlertsCount").transform([alert()] * 5000)["transformedResponse"]
    assert tr["countIsLowerBound"] is True
    for n in (3, 200, 4900):
        tr = load("openSecretScanningAlertsCount").transform([alert()] * n)["transformedResponse"]
        assert tr["countIsLowerBound"] is False
