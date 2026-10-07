"""Microsoft Entra ID isMFAConfiguredForSecurityAdmins: every security admin role, every sign-in, or no answer.

The check passed when one enabled MFA policy covered any one of its six roles, so a tenant that left Privileged
Authentication Administrator out of its admin policy was graded as configured. It now passes only when all six
are covered by an enabled policy that requires MFA for every cloud app (or the Microsoft Admin Portals) and is
not limited to risky sign-ins. A body that is not a policy collection, a partial page that leaves a role
uncovered, and a transformation error return None with dataCollection.status "error".

The two Microsoft policies below are from the List policies example response in Microsoft Graph's v1.0
reference (CA001 requires MFA for 15 admin roles; CA008 asks high-risk users for a password change under an MFA
authentication strength). Role ids are Microsoft's public built-in role template ids. Each case runs as plain
Python and in the Token-Service sandbox replica.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "entrasecadminverdict"
KEY = "isMFAConfiguredForSecurityAdmins"

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
PRIV_AUTH_ADMIN = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"

CA001 = {
    "id": "2b31ac51-b855-40a5-a986-0a4ed23e9008",
    "displayName": "CA001: Require multi-factor authentication for admins",
    "state": "enabled",
    "conditions": {
        "userRiskLevels": [], "signInRiskLevels": [], "clientAppTypes": ["all"],
        "applications": {"includeApplications": ["All"], "excludeApplications": []},
        "users": {"includeUsers": [], "excludeUsers": [], "includeGroups": [],
                  "excludeGroups": ["eedad040-3722-4bcb-bde5-bc7c857f4983"],
                  "includeRoles": ["62e90394-69f5-4237-9190-012177145e10", "194ae4cb-b126-40b2-bd5b-6091b380977d",
                                   "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", "29232cdf-9323-42fd-ade2-1d097af3e4de",
                                   "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9", "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                                   "b0f54661-2d74-4c50-afa3-1ec803f12efe", "fe930be7-5e62-47db-91af-98c3a49a38b1",
                                   "c4e39bd9-1100-46d3-8c65-fb160da0071f", "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                                   "158c047a-c907-4556-b7ef-446551a6b5f7", "966707d0-3269-4727-9be2-8c3a10f19b9d",
                                   "7be44c8a-adaf-4e2a-84d6-ab2649e08a13", "e8611ab8-c189-46e8-94e1-60213ab1f814",
                                   "f2ef992c-3afb-46b9-b7cf-a126ee74c451"],
                  "excludeRoles": []}},
    "grantControls": {"operator": "OR", "builtInControls": ["mfa"], "authenticationStrength": None},
}
CA008 = {
    "id": "10ef4fe6-5e51-4f5e-b5a2-8fed19d0be67",
    "displayName": "CA008: Require password change for high-risk users",
    "state": "enabled",
    "conditions": {
        "userRiskLevels": ["high"], "signInRiskLevels": [], "clientAppTypes": ["all"],
        "applications": {"includeApplications": ["All"], "excludeApplications": []},
        "users": {"includeUsers": ["All"], "excludeUsers": [], "includeGroups": [],
                  "excludeGroups": ["eedad040-3722-4bcb-bde5-bc7c857f4983"], "includeRoles": [], "excludeRoles": []}},
    "grantControls": {"operator": "AND", "builtInControls": ["passwordChange"],
                      "authenticationStrength": {"id": "00000000-0000-0000-0000-000000000002",
                                                 "displayName": "Multifactor authentication",
                                                 "requirementsSatisfied": "mfa"}},
}


def load(mode):
    path = HERE / "ismfaconfiguredforsecurityadmins.py"
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def graph(*policies, next_link=False):
    body = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#conditionalAccess/policies",
            "value": [copy.deepcopy(p) for p in policies]}
    if next_link:
        body["@odata.nextLink"] = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$skiptoken=x"
    return body


def edited(policy, **changes):
    out = copy.deepcopy(policy)
    for path, value in changes.items():
        node = out
        keys = path.split("__")
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
    return out


class Poisoned(dict):
    def __getattribute__(self, name):
        raise RuntimeError("poisoned read")

    def __getitem__(self, key):
        raise RuntimeError("poisoned read")

    def __contains__(self, key):
        raise RuntimeError("poisoned read")


def pair(out):
    return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("mode", MODES)
def test_microsoft_example_passes(mode):
    out = load(mode)(graph(CA001, CA008))
    assert pair(out) == (True, "success")
    assert len(out["transformedResponse"]["coveredRoles"]) == 6


@pytest.mark.parametrize("mode", MODES)
def test_privileged_authentication_administrator_left_out_fails(mode):
    roles = [r for r in CA001["conditions"]["users"]["includeRoles"] if r != PRIV_AUTH_ADMIN]
    out = load(mode)(graph(edited(CA001, conditions__users__includeRoles=roles), CA008))
    assert pair(out) == (False, "success")
    assert out["additionalInfo"]["evaluation"]["failReasons"][0].endswith(
        "not covered: Privileged Authentication Administrator")


@pytest.mark.parametrize("mode", MODES)
def test_a_risk_scoped_policy_does_not_count(mode):
    assert pair(load(mode)(graph(CA008))) == (False, "success")
    sign_in_risk = edited(CA001, conditions__signInRiskLevels=["medium", "high"])
    assert pair(load(mode)(graph(sign_in_risk))) == (False, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("state", ["enabledForReportingButNotEnforced", "disabled"])
def test_a_policy_not_enforced_does_not_count(mode, state):
    assert pair(load(mode)(graph(edited(CA001, state=state)))) == (False, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("apps,expected", [(["All"], True), (["MicrosoftAdminPortals"], True),
                                           (["00000002-0000-0ff1-ce00-000000000000"], False)])
def test_policy_must_apply_to_every_app_or_the_admin_portals(mode, apps, expected):
    out = load(mode)(graph(edited(CA001, conditions__applications__includeApplications=apps)))
    assert pair(out) == (expected, "success")


@pytest.mark.parametrize("mode", MODES)
def test_partial_page_that_covers_every_role_still_passes(mode):
    assert pair(load(mode)(graph(CA001, next_link=True))) == (True, "success")


@pytest.mark.parametrize("mode", MODES)
def test_partial_page_that_leaves_a_role_uncovered_is_not_evaluated(mode):
    assert pair(load(mode)(graph(CA008, next_link=True))) == (None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_no_policies_is_measured_false(mode):
    assert pair(load(mode)(graph())) == (False, "success")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [
    {"error": {"code": "Authorization_RequestDenied", "message": "Insufficient privileges to complete the operation."}},
    {"error": {"code": "Forbidden"}, "value": []},
    {},
    None,
    "",
    "not json",
    {"conditionalAccessPolicies": {"error": {"code": "Forbidden"}}},
], ids=["graph-error", "error-beside-value", "empty-object", "null", "empty-string", "not-json", "merged-error"])
def test_no_evidence_is_not_evaluated(mode, body):
    out = load(mode)(body)
    assert pair(out) == (None, "error")
    assert out["additionalInfo"]["dataCollection"]["errors"]


@pytest.mark.parametrize("mode", MODES)
def test_poisoned_body_is_not_evaluated(mode):
    out = load(mode)(Poisoned())
    assert pair(out) == (None, "error")
    assert out["additionalInfo"]["dataCollection"]["errors"][0].startswith("Transformation error")
