"""authTypesAllowed while the authentication methods policy is still migrating.

Until policyMigrationState is migrationComplete, Microsoft still applies the legacy per-user MFA and SSPR
policies, and they can allow text message, voice call or other methods that this endpoint cannot read. A
method list here with no weak method in it is then not evidence that no weak method is allowed, so the
pass becomes not evaluated (dataCollection error naming the state). A weak method enabled here still
fails in any state. Only migrationComplete passes. A policy that reports no state (key missing, null or an
empty string) does not show the migration is complete, so a clean list there is not evaluated as well.

Three live copies read the same Graph body: the Azure reader, the byte-identical Azure AD One-Click copy,
and the older Microsoft 365 copy. Synthetic bodies only.
"""
import copy
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SAFEGUARDS = HERE.parent.parent

AZURE_PATH = HERE / "authtypesallowed.py"
ONECLICK_PATH = SAFEGUARDS / "d9b6f27a-2e67-4b55-a09e-0784c5de9abd" / "auth_types_allowed.py"
M365_PATH = SAFEGUARDS / "874a78ff-2ca3-4c0e-ab86-19277536ac87" / "authtypesallowed.py"
PATHS = [AZURE_PATH, ONECLICK_PATH, M365_PATH]
KEY = "authTypesAllowed"

MISSING = object()  # policyMigrationState key left out of the body entirely
NO_STATES = [MISSING, None, "", "   "]
LEGACY_STATES = ["preMigration", "migrationInProgress", "MigrationInProgress", "PREMIGRATION"]
ALL_IDS = ["Email", "Fido2", "MicrosoftAuthenticator", "Sms", "SoftwareOath", "TemporaryAccessPass", "Voice",
           "X509Certificate"]


def load(path):
    spec = importlib.util.spec_from_file_location("authtypes_migration_" + path.parent.name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MODULES = {path: load(path) for path in PATHS}


def policy(enabled, state):
    configs = [{"id": i, "state": "enabled" if i in enabled else "disabled",
                "includeTargets": [{"targetType": "group", "id": "all_users"}]} for i in ALL_IDS]
    body = {"id": "authenticationMethodsPolicy", "authenticationMethodConfigurations": configs}
    if state is not MISSING:
        body["policyMigrationState"] = state
    return body


def run(path, body):
    return MODULES[path].transform(copy.deepcopy(body))


def verdict(out):
    return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]


def errors(out):
    return " ".join(out["additionalInfo"]["dataCollection"]["errors"])


@pytest.mark.parametrize("path", PATHS, ids=lambda p: p.parent.name)
@pytest.mark.parametrize("state", LEGACY_STATES)
def test_a_clean_list_while_migrating_is_not_evaluated(path, state):
    out = run(path, policy(["Fido2", "MicrosoftAuthenticator"], state))
    assert verdict(out) == (False, "error")
    assert "policyMigrationState is " + state in errors(out)
    assert "legacy per-user MFA and SSPR policies still apply" in errors(out)
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []


@pytest.mark.parametrize("path", PATHS, ids=lambda p: p.parent.name)
def test_an_unrecognised_state_is_not_treated_as_complete(path):
    assert verdict(run(path, policy(["Fido2"], "someFutureState"))) == (False, "error")


def state_id(state):
    return "missing" if state is MISSING else repr(state)


@pytest.mark.parametrize("path", PATHS, ids=lambda p: p.parent.name)
@pytest.mark.parametrize("state", LEGACY_STATES + ["migrationComplete"] + NO_STATES, ids=state_id)
def test_a_weak_method_enabled_here_still_fails_in_any_state(path, state):
    out = run(path, policy(["Fido2", "Sms"], state))
    assert verdict(out) == (False, "success")
    assert "Sms" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


@pytest.mark.parametrize("path", PATHS, ids=lambda p: p.parent.name)
@pytest.mark.parametrize("state", ["migrationComplete", "MIGRATIONCOMPLETE"])
def test_a_clean_list_once_migrated_passes(path, state):
    out = run(path, policy(["Fido2", "MicrosoftAuthenticator"], state))
    assert verdict(out) == (True, "success")
    assert out["additionalInfo"]["dataCollection"]["errors"] == []


@pytest.mark.parametrize("path", PATHS, ids=lambda p: p.parent.name)
@pytest.mark.parametrize("state", NO_STATES, ids=state_id)
def test_a_clean_list_with_no_state_reported_is_not_evaluated(path, state):
    # A policy that reports no policyMigrationState (key missing, null or empty) does not
    # show the migration is complete, so it reads like a not-complete state rather than a pass.
    out = run(path, policy(["Fido2", "MicrosoftAuthenticator"], state))
    assert verdict(out) == (False, "error")
    assert "migration state was not reported" in errors(out)
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []
    assert out["transformedResponse"][KEY] is not True


@pytest.mark.parametrize("state", LEGACY_STATES + ["migrationComplete"] + NO_STATES, ids=state_id)
def test_m365_nothing_enabled_is_not_evaluated(state):
    # It used to pass with "No authentication methods configured": the vacuous truth of an empty list.
    out = run(M365_PATH, policy([], state))
    assert verdict(out) == (False, "error")
    assert out["additionalInfo"]["evaluation"]["passReasons"] == []
    if state is not MISSING and state and state.strip():
        assert "policyMigrationState: " + state in errors(out)


def test_the_one_click_copy_is_byte_identical():
    assert AZURE_PATH.read_bytes() == ONECLICK_PATH.read_bytes()


def sandbox_transform(path):
    """The same file under the production RestrictedPython replica (skipped when it is not installed)."""
    pytest.importorskip("RestrictedPython")
    spec = importlib.util.spec_from_file_location("restricted_sandbox_authtypes_migration",
                                                  SAFEGUARDS.parent / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    return sandbox.load(path.read_text(), "<transformation>")["transform"]


@pytest.mark.parametrize("path", PATHS, ids=lambda p: p.parent.name)
def test_the_production_sandbox_gives_the_same_verdicts(path):
    transform = sandbox_transform(path)
    assert verdict(transform(policy(["Fido2"], "migrationInProgress"))) == (False, "error")
    assert verdict(transform(policy(["Fido2", "Sms"], "preMigration"))) == (False, "success")
    assert verdict(transform(policy(["Fido2"], "migrationComplete"))) == (True, "success")
    assert verdict(transform(policy(["Fido2"], MISSING))) == (False, "error")
    assert verdict(transform(policy(["Fido2"], None))) == (False, "error")
    assert verdict(transform(policy(["Fido2"], ""))) == (False, "error")
    assert verdict(transform(policy(["Fido2", "Sms"], MISSING))) == (False, "success")
