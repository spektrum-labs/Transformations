"""Microsoft - Cloud Security isRootUserMFAEnabled: Global Administrator MFA, break-glass allowed.

"Root user" is AWS's term; on Microsoft the equivalent is Global Administrator (product decision
2026-11-16). The transform is ismfaconfiguredforsecurityadmins.py narrowed to that one role: an enabled
Conditional Access policy must require MFA for every cloud app (or the admin portals) and target
Global Administrator, excluding at most break-glass (2 named accounts or 1 group). Exclusions beyond that,
an unread or partial policy list, an error body and a crash are None with dataCollection.status "error".
The reasons carry counts only, never the excluded accounts.

Role ids are Microsoft's public built-in role template ids; every other id is synthetic.
Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "entrarootusermfa"
KEY = "isRootUserMFAEnabled"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
BREAK_GLASS_1 = "00000000-0000-4000-8000-000000000001"
BREAK_GLASS_2 = "00000000-0000-4000-8000-000000000002"
BREAK_GLASS_3 = "00000000-0000-4000-8000-000000000003"
GROUP = "00000000-0000-4000-8000-0000000000a1"

try:
    import RestrictedPython  # noqa: F401
    _spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    _sandbox = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_sandbox)
    load_code = _sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(mode):
    path = HERE / "isrootusermfaenabled.py"
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def policy(roles=(GLOBAL_ADMIN,), state="enabled", exclude_users=(), exclude_groups=(), apps=("All",)):
    return {
        "id": "11111111-1111-4111-8111-111111111111",
        "displayName": "Require MFA for admins",
        "state": state,
        "conditions": {
            "userRiskLevels": [], "signInRiskLevels": [], "clientAppTypes": ["all"],
            "applications": {"includeApplications": list(apps), "excludeApplications": []},
            "users": {"includeUsers": [], "excludeUsers": list(exclude_users), "includeGroups": [],
                      "excludeGroups": list(exclude_groups), "includeRoles": list(roles), "excludeRoles": []}},
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"], "authenticationStrength": None},
    }


def graph(*policies, next_link=False):
    body = {"value": [copy.deepcopy(p) for p in policies]}
    if next_link:
        body["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=x"
    return body


def pair(out):
    return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("mode", MODES)
def test_global_admin_mfa_policy_passes(mode):
    out = load(mode)(graph(policy()))
    assert pair(out) == (True, "success")


@pytest.mark.parametrize("mode", MODES)
def test_all_users_policy_passes(mode):
    p = policy(roles=())
    p["conditions"]["users"]["includeUsers"] = ["All"]
    assert pair(load(mode)(graph(p))) == (True, "success")


@pytest.mark.parametrize("mode", MODES)
def test_break_glass_is_allowed_and_only_counted(mode):
    out = load(mode)(graph(policy(exclude_users=(BREAK_GLASS_1, BREAK_GLASS_2))))
    assert pair(out) == (True, "success")
    text = json.dumps(out["additionalInfo"]["evaluation"])
    assert "2 account(s), 0 group(s)" in text
    assert BREAK_GLASS_1 not in text and BREAK_GLASS_2 not in text


@pytest.mark.parametrize("mode", MODES)
def test_policy_for_other_roles_only_is_a_measured_fail(mode):
    out = load(mode)(graph(policy(roles=(SECURITY_ADMIN,))))
    assert pair(out) == (False, "success")


@pytest.mark.parametrize("mode", MODES)
def test_report_only_policy_is_a_measured_fail(mode):
    assert pair(load(mode)(graph(policy(state="enabledForReportingButNotEnforced")))) == (False, "success")


@pytest.mark.parametrize("mode", MODES)
def test_no_policies_is_a_measured_fail(mode):
    assert pair(load(mode)(graph())) == (False, "success")


@pytest.mark.parametrize("mode", MODES)
def test_exclusions_beyond_break_glass_are_unknown(mode):
    out = load(mode)(graph(policy(exclude_users=(BREAK_GLASS_1, BREAK_GLASS_2, BREAK_GLASS_3))))
    assert pair(out) == (None, "error")
    out = load(mode)(graph(policy(exclude_users=(BREAK_GLASS_1,), exclude_groups=(GROUP,))))
    assert pair(out) == (None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_partial_page_without_coverage_is_unknown(mode):
    assert pair(load(mode)(graph(policy(roles=(SECURITY_ADMIN,)), next_link=True))) == (None, "error")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [None, {}, "not json", {"error": True, "statusCode": 504, "message": "Gateway Timeout"},
                                  {"error": {"code": "Authorization_RequestDenied", "message": "denied"}}])
def test_unread_policy_list_is_unknown(mode, body):
    out = load(mode)(body)
    assert pair(out) == (None, "error")
    assert out["additionalInfo"]["dataCollection"]["errors"]


def test_a_crash_is_unknown():
    class Poisoned(dict):
        def __getattribute__(self, name):
            raise RuntimeError("poisoned read")

        def __contains__(self, key):
            raise RuntimeError("poisoned read")

    assert pair(load("python")(Poisoned())) == (None, "error")
