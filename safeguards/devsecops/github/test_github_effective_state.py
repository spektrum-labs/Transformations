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
    ("openSecretScanningAlertsCount", "openSecretScanningAlertsCount", [], 0, [alert()] * 100, None),
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
