"""Okta isMFAEnforcedForUsers / isMFAEnabled: a read that proves nothing is not evaluated, never a gap.

Both keys come from the getMfaPolicyRules merge (signOnPolicies, signOnRules, accessPolicies, accessRules). An
error body, an empty object, a misaligned rule list, a policy set where no rule allows sign-on, a transformation
error, and an allowing rule whose verification method this file does not read (AUTH_METHOD_CHAIN) used to return
False under dataCollection.status "success", which Token-Service grades as a measured FAILED. Each now returns
None on both keys with dataCollection.status "error". Okta's system Default policy is judged by its rules: with
requireFactor false it fails. Synthetic policies only. Each case runs as plain Python and in the Token-Service
sandbox replica.
"""
import copy
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "oktamfanotmeasured"
KEY = "isMFAEnforcedForUsers"

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
    path = HERE / "ismfaenforcedforusers.py"
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def access_rule(name, factor_mode="2FA", method_type="ASSURANCE", access="ALLOW", system=False):
    return {"name": name, "status": "ACTIVE", "system": system,
            "actions": {"appSignOn": {"access": access,
                                      "verificationMethod": {"type": method_type, "factorMode": factor_mode}}}}


def signon_rule(name, require_factor, system=False):
    return {"name": name, "status": "ACTIVE", "system": system,
            "actions": {"signon": {"access": "ALLOW", "requireFactor": require_factor}}}


def policy(name, kind="APP", system=False):
    return {"name": name, "status": "ACTIVE", "system": system, "_embedded": {"resourceType": kind}}


def identity_engine(*app_rules):
    """Two app policies and the account management policy, shaped as the merge returns them."""
    rules = list(app_rules) or [access_rule("Catch-all Rule", system=True)]
    return {"result": {
        "signOnPolicies": [policy("Default Policy", kind="", system=True)],
        "signOnRules": [[signon_rule("Default Rule", False, system=True)]],
        "accessPolicies": [policy("Any two factors", system=True), policy("App policy"),
                           policy("Okta Account Management Policy", kind="END_USER_ACCOUNT_MANAGEMENT")],
        "accessRules": [[access_rule("Catch-all Rule", system=True)], rules,
                        [access_rule("Recovery", factor_mode="1FA")]],
    }}


def classic(require_factor):
    """Classic Engine: no authentication policies, only Okta's system Default global session policy."""
    return {"signOnPolicies": [policy("Default Policy", kind="", system=True)],
            "signOnRules": [[signon_rule("Default Rule", require_factor, system=True)]],
            "accessPolicies": [], "accessRules": []}


class Poisoned(dict):
    def __getattribute__(self, name):
        raise RuntimeError("poisoned read")

    def __getitem__(self, key):
        raise RuntimeError("poisoned read")

    def __contains__(self, key):
        raise RuntimeError("poisoned read")


def pair(out):
    return (out["transformedResponse"][KEY], out["transformedResponse"]["isMFAEnabled"],
            out["additionalInfo"]["dataCollection"]["status"])


@pytest.mark.parametrize("mode", MODES)
def test_every_allowing_rule_two_factor_passes(mode):
    assert pair(load(mode)(identity_engine(access_rule("Employees")))) == (True, True, "success")


@pytest.mark.parametrize("mode", MODES)
def test_one_single_factor_rule_fails_and_is_measured(mode):
    out = load(mode)(identity_engine(access_rule("Employees"), access_rule("Kiosk", factor_mode="1FA")))
    assert pair(out) == (False, True, "success")
    assert any("App policy / Kiosk (factorMode 1FA)" in r for r in out["additionalInfo"]["evaluation"]["failReasons"])


@pytest.mark.parametrize("mode", MODES)
def test_account_management_policy_is_not_judged(mode):
    out = load(mode)(identity_engine(access_rule("Employees")))
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert summary["policiesNotJudged"] == ["Okta Account Management Policy (END_USER_ACCOUNT_MANAGEMENT)"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("require_factor,expected", [(False, (False, False, "success")),
                                                     (True, (True, True, "success"))])
def test_classic_system_default_policy_is_judged_by_its_rule(mode, require_factor, expected):
    assert pair(load(mode)(classic(require_factor))) == expected


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", [
    {"errorCode": "E0000006", "errorSummary": "You do not have permission to perform the requested action"},
    {},
    {"result": {}},
    [],
    None,
    "",
    b"\xff",
    {"accessPolicies": [policy("App policy")], "accessRules": []},
    {"accessPolicies": [policy("App policy")], "accessRules": [{"error": True}]},
    {"accessPolicies": [policy("App policy")], "accessRules": [[]]},
    {"accessPolicies": [], "accessRules": [], "signOnPolicies": [], "signOnRules": []},
], ids=["error-envelope", "empty-object", "wrapped-empty", "list", "null", "empty-string", "bad-bytes",
        "rules-missing", "rules-unreadable", "no-active-rules", "no-policies"])
def test_no_evidence_is_not_evaluated(mode, body):
    out = load(mode)(body)
    assert pair(out) == (None, None, "error")
    assert out["additionalInfo"]["dataCollection"]["errors"]


@pytest.mark.parametrize("mode", MODES)
def test_poisoned_body_is_not_evaluated(mode):
    out = load(mode)(Poisoned())
    assert pair(out) == (None, None, "error")
    assert out["additionalInfo"]["dataCollection"]["errors"][0].startswith("Transformation error")


@pytest.mark.parametrize("mode", MODES)
def test_no_allowing_rule_is_not_evaluated(mode):
    body = identity_engine(access_rule("Blocked", access="DENY"))
    body["result"]["accessRules"][0] = [access_rule("Catch-all Rule", access="DENY", system=True)]
    assert pair(load(mode)(body)) == (None, None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_unread_verification_method_alone_is_not_evaluated(mode):
    body = identity_engine(access_rule("Chained", method_type="AUTH_METHOD_CHAIN", factor_mode=""))
    body["result"]["accessRules"][0] = [access_rule("Catch-all Rule", method_type="AUTH_METHOD_CHAIN",
                                                    factor_mode="", system=True)]
    out = load(mode)(body)
    assert pair(out) == (None, None, "error")
    assert "AUTH_METHOD_CHAIN" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("mode", MODES)
def test_unread_method_beside_a_two_factor_rule_withholds_both_keys(mode):
    """isMFAEnabled was True here while the status said error. Token-Service grades on that status alone, so
    the value was discarded anyway -- it only read as a measurement to anything else looking at
    transformedResponse. Both keys are None, and the sound half is stated in dataCollection.errors."""
    out = load(mode)(identity_engine(access_rule("Employees"),
                                     access_rule("Chained", method_type="AUTH_METHOD_CHAIN", factor_mode="")))
    assert pair(out) == (None, None, "error")
    assert any("isMFAEnabled is True on the rules that could be read" in e
               for e in out["additionalInfo"]["dataCollection"]["errors"])


@pytest.mark.parametrize("mode", MODES)
def test_a_single_factor_rule_still_fails_beside_an_unread_one(mode):
    """Unchanged, and the reason the mirror case below needs the system rule replaced: the Catch-all rule
    requires two factors, so both keys are measured here and nothing is withheld."""
    out = load(mode)(identity_engine(access_rule("Kiosk", factor_mode="1FA"),
                                     access_rule("Chained", method_type="AUTH_METHOD_CHAIN", factor_mode="")))
    assert pair(out) == (False, True, "success")


@pytest.mark.parametrize("mode", MODES)
def test_a_single_factor_rule_beside_an_unread_one_withholds_both_keys(mode):
    """The mirror case, with no two-factor rule anywhere: isMFAEnforcedForUsers was False beside a None under
    the same discarding status. The single-factor path stays in the reasons and in dataCollection.errors,
    where it is not mistaken for a verdict the evaluator will ever read."""
    body = identity_engine(access_rule("Kiosk", factor_mode="1FA"),
                           access_rule("Chained", method_type="AUTH_METHOD_CHAIN", factor_mode=""))
    body["result"]["accessRules"][0] = [access_rule("Catch-all Rule", method_type="AUTH_METHOD_CHAIN",
                                                    factor_mode="", system=True)]
    out = load(mode)(body)
    assert pair(out) == (None, None, "error")
    assert any("isMFAEnforcedForUsers is False on the rules that could be read" in e
               for e in out["additionalInfo"]["dataCollection"]["errors"])
    assert any("App policy / Kiosk (factorMode 1FA)" in r
               for r in out["additionalInfo"]["evaluation"]["failReasons"])


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("build", [
    lambda: identity_engine(access_rule("Employees"),
                            access_rule("Chained", method_type="AUTH_METHOD_CHAIN", factor_mode="")),
    lambda: {"errorCode": "E0000006",
             "errorSummary": "You do not have permission to perform the requested action"},
    lambda: {},
    Poisoned,
], ids=["mixed-unread", "error-body", "empty-object", "poisoned"])
def test_a_not_measured_output_recommends_nothing(mode, build):
    """`all(result.values())` was False for a None as well as for a False, so a read that measured nothing
    still told the customer to require two factors on every rule."""
    out = load(mode)(build())
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["evaluation"]["recommendations"] == []


@pytest.mark.parametrize("mode", MODES)
def test_a_measured_false_still_recommends_the_fix(mode):
    """The other half: suppressing the recommendation must not suppress it where it is earned."""
    out = load(mode)(identity_engine(access_rule("Employees"), access_rule("Kiosk", factor_mode="1FA")))
    assert out["transformedResponse"][KEY] is False
    assert out["additionalInfo"]["evaluation"]["recommendations"] == [
        "Require two factors (factorMode 2FA) on every rule that allows access in every Okta "
        "authentication policy"]


@pytest.mark.parametrize("mode", MODES)
def test_input_is_not_mutated(mode):
    body = identity_engine(access_rule("Employees"))
    before = copy.deepcopy(body)
    load(mode)(body)
    assert body == before
