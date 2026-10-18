"""Entra MFA keys while the authentication methods policy is still migrating.

policyMigrationState is preMigration or migrationInProgress: the legacy per-user MFA and SSPR policies still decide
which methods members can use, and they cannot be read here. A new-policy method list with no strong method in it
is then not evidence that MFA is unavailable, so these keys read not evaluated (value None, dataCollection error
naming the state), never False. A strong method enabled in the new policy is still positive evidence and still
passes. Once the state is migrationComplete, or the policy carries no state, the existing verdicts are unchanged.
Synthetic bodies only.
"""
import copy
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SAFEGUARDS = HERE.parent.parent


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


USERS = load(HERE / "ismfaenforcedforusers.py", "entra_users_migration")
ENABLED = load(HERE / "ismfaenabled.py", "entra_enabled_migration")
ENFORCED = load(HERE / "ismfaenforced.py", "entra_enforced_migration")
M365 = load(SAFEGUARDS / "874a78ff-2ca3-4c0e-ab86-19277536ac87" / "ismfaenforcedforusers.py", "m365_users_migration")

LEGACY_STATES = ["preMigration", "migrationInProgress", "PREMIGRATION", "MigrationInProgress"]
DUO = {"@odata.type": "#microsoft.graph.externalAuthenticationMethodConfiguration", "id": "ext-1",
       "displayName": "External MFA", "state": "enabled"}
ALL_USERS_MFA = {"displayName": "Require MFA for everyone", "state": "enabled",
                 "grantControls": {"builtInControls": ["mfa"], "operator": "OR"},
                 "conditions": {"users": {"includeUsers": ["All"], "excludeUsers": [], "includeGroups": [],
                                          "excludeGroups": [], "includeRoles": [], "excludeRoles": []},
                                "applications": {"includeApplications": ["All"], "excludeApplications": []},
                                "clientAppTypes": ["all"]}}


def methods(enabled, state, extra=()):
    ids = ["MicrosoftAuthenticator", "Fido2", "SoftwareOath", "TemporaryAccessPass", "Sms", "Voice", "Email"]
    configs = [{"id": i, "state": "enabled" if i in enabled else "disabled", "includeTargets": [
        {"targetType": "group", "id": "all_users"}]} for i in ids] + [copy.deepcopy(e) for e in extra]
    policy = {"id": "authenticationMethodsPolicy", "authenticationMethodConfigurations": configs}
    if state is not None:
        policy["policyMigrationState"] = state
    return policy


def graph_input(enabled, state, ca=(ALL_USERS_MFA,), extra=()):
    return {"authMethodsPolicy": methods(enabled, state, extra), "conditionalAccessPolicies": {"value": list(ca)}}


def run(module, body):
    return module.transform(copy.deepcopy(body))


def value(out, key):
    return out["transformedResponse"][key]


def errors(out):
    return out["additionalInfo"]["dataCollection"]["errors"]


GRAPH_CASES = [(USERS, "isMFAEnforcedForUsers"), (ENABLED, "isMFAEnabled"), (ENFORCED, "isMFAEnforced")]


@pytest.mark.parametrize("module,key", GRAPH_CASES)
@pytest.mark.parametrize("state", LEGACY_STATES)
def test_a_migrating_policy_does_not_hide_a_missing_mfa_conditional_access_policy(module, key, state):
    # No Conditional Access policy requires MFA: False whatever the method list says, so the migration state
    # (which only explains the method list) must not turn it into not evaluated.
    out = run(module, graph_input(["Sms", "Voice"], state, ca=()))
    assert value(out, key) is False


@pytest.mark.parametrize("state", LEGACY_STATES)
def test_a_migrating_policy_does_not_hide_a_risk_only_mfa_policy(state):
    # MFA is required only on sign-in risk: never all-user enforcement, so isMFAEnforcedForUsers keeps its False
    # whatever the (migrating) method list says.
    risk_only = copy.deepcopy(ALL_USERS_MFA)
    risk_only["displayName"] = "MFA on risky sign-in"
    risk_only["conditions"]["signInRiskLevels"] = ["high", "medium"]
    out = run(USERS, graph_input(["Sms", "Voice"], state, ca=(risk_only,)))
    assert value(out, "isMFAEnforcedForUsers") is False


@pytest.mark.parametrize("module,key", GRAPH_CASES)
@pytest.mark.parametrize("state", LEGACY_STATES)
def test_only_weak_methods_in_a_migrating_policy_is_not_evaluated(module, key, state):
    out = run(module, graph_input(["Sms", "Voice"], state))
    assert value(out, key) is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert "policyMigrationState" in errors(out)[0] and state in errors(out)[0]
    assert "legacy" in errors(out)[0]


@pytest.mark.parametrize("module,key", GRAPH_CASES)
@pytest.mark.parametrize("state", LEGACY_STATES)
def test_nothing_that_counts_enabled_even_with_a_policy_requiring_mfa_is_not_evaluated(module, key, state):
    out = run(module, graph_input(["Email"], state))
    assert value(out, key) is None


@pytest.mark.parametrize("module,key", GRAPH_CASES)
@pytest.mark.parametrize("state", LEGACY_STATES)
def test_a_strong_method_still_passes_in_a_migrating_policy(module, key, state):
    out = run(module, graph_input(["MicrosoftAuthenticator"], state))
    assert value(out, key) is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("module,key", GRAPH_CASES)
@pytest.mark.parametrize("state", ["migrationComplete", "MIGRATIONCOMPLETE", None])
def test_complete_or_unreported_state_keeps_the_false_verdict(module, key, state):
    out = run(module, graph_input(["Sms", "Voice"], state))
    assert value(out, key) is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("module,key", GRAPH_CASES)
def test_an_unrecognised_state_is_treated_as_not_complete(module, key):
    out = run(module, graph_input(["Sms"], "somethingNew"))
    assert value(out, key) is None
    assert "somethingNew" in errors(out)[0]


def test_users_external_method_keeps_its_own_reason_in_a_migrating_policy():
    out = run(USERS, graph_input([], "migrationInProgress", extra=[DUO]))
    assert value(out, "isMFAEnforcedForUsers") is None
    assert "external authentication method" in errors(out)[0]


def test_users_state_text_is_not_echoed_unbounded():
    out = run(USERS, graph_input(["Sms"], "x" * 500))
    assert value(out, "isMFAEnforcedForUsers") is None
    assert len(errors(out)[0]) < 400


def m365(enabled, state, extra=()):
    return methods(enabled, state, extra)


@pytest.mark.parametrize("state", LEGACY_STATES)
def test_m365_weak_only_in_a_migrating_policy_is_not_evaluated(state):
    out = run(M365, m365(["Sms"], state))
    assert value(out, "isMFAEnforcedForUsers") is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert state in errors(out)[0] and "legacy" in errors(out)[0]


@pytest.mark.parametrize("state", LEGACY_STATES)
def test_m365_other_method_only_in_a_migrating_policy_is_not_evaluated(state):
    out = run(M365, m365([], state, extra=[{"id": "X509Certificate", "state": "enabled"}]))
    assert value(out, "isMFAEnforcedForUsers") is None


@pytest.mark.parametrize("state", LEGACY_STATES)
def test_m365_strong_method_still_passes_in_a_migrating_policy(state):
    out = run(M365, m365(["MicrosoftAuthenticator"], state))
    assert value(out, "isMFAEnforcedForUsers") is True


@pytest.mark.parametrize("state", ["migrationComplete", None])
def test_m365_complete_or_unreported_state_keeps_the_false_verdict(state):
    out = run(M365, m365(["Sms"], state))
    assert value(out, "isMFAEnforcedForUsers") is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def sandbox_transform(path):
    """The same file under the production RestrictedPython replica (skipped when it is not installed)."""
    pytest.importorskip("RestrictedPython")
    spec = importlib.util.spec_from_file_location("restricted_sandbox_migration", SAFEGUARDS.parent / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load(Path(path).read_text(), "<transformation>")["transform"]


@pytest.mark.parametrize("path,key,body", [
    (HERE / "ismfaenforcedforusers.py", "isMFAEnforcedForUsers", graph_input(["Sms"], "migrationInProgress")),
    (HERE / "ismfaenabled.py", "isMFAEnabled", graph_input(["Sms"], "preMigration")),
    (HERE / "ismfaenforced.py", "isMFAEnforced", graph_input(["Sms"], "preMigration")),
    (SAFEGUARDS / "874a78ff-2ca3-4c0e-ab86-19277536ac87" / "ismfaenforcedforusers.py", "isMFAEnforcedForUsers",
     methods(["Sms"], "migrationInProgress")),
])
def test_migrating_weak_only_is_not_evaluated_in_the_production_sandbox(path, key, body):
    out = sandbox_transform(path)(copy.deepcopy(body))
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
