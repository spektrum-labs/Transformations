"""Okta isMFAEnabled answers from its own evidence: one readable two-factor rule is enough.

A body with seven allowing sign-on rules, two of which require two factors and five of which use a verification
method this code does not read (AUTH_METHOD_CHAIN), used to lose its isMFAEnabled True once the shared file
started withholding both keys together. isMFAEnabled is True there: the two readable rules prove MFA is enabled
and the five unread ones cannot undo that. isMFAEnforcedForUsers cannot be proven with five rules unread, so the
shared file reports it Not evaluated. Synthetic policies only. Each case runs as plain Python and in the
Token-Service sandbox replica.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TAG = "oktamfaenabled"

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


def load(mode, filename="ismfaenabled.py"):
    path = HERE / filename
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + filename.replace(".py", ""), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def enabled(mode, body):
    return load(mode)(body)


def enforced(mode, body):
    return load(mode, "ismfaenforcedforusers.py")(body)


def rule(name, factor_mode="2FA", method_type="ASSURANCE", access="ALLOW"):
    return {"name": name, "status": "ACTIVE", "system": False,
            "actions": {"appSignOn": {"access": access,
                                      "verificationMethod": {"type": method_type, "factorMode": factor_mode}}}}


def chained(name):
    return rule(name, method_type="AUTH_METHOD_CHAIN", factor_mode="")


def policy(name, kind="APP"):
    return {"name": name, "status": "ACTIVE", "system": False, "_embedded": {"resourceType": kind}}


def body(*policies):
    """Identity Engine merge: one (policy name, [rules]) pair per authentication policy."""
    return {"result": {
        "signOnPolicies": [policy("Default Policy", kind="")],
        "signOnRules": [[{"name": "Default Rule", "status": "ACTIVE", "system": True,
                          "actions": {"signon": {"access": "ALLOW", "requireFactor": False}}}]],
        "accessPolicies": [policy(name) for name, rules in policies],
        "accessRules": [rules for name, rules in policies],
    }}


def seven_rules(two_factor=2, unread=5):
    """Seven allowing rules across two policies: `two_factor` readable two-factor rules, `unread` chained ones."""
    policies = []
    if two_factor:
        policies.append(("Two factor policy", [rule("Employees " + str(i)) for i in range(two_factor)]))
    if unread:
        policies.append(("Chained policy", [chained("Chained " + str(i)) for i in range(unread)]))
    return body(*policies)


def classic(require_factor):
    return {"signOnPolicies": [policy("Default Policy", kind="")],
            "signOnRules": [[{"name": "Default Rule", "status": "ACTIVE", "system": True,
                              "actions": {"signon": {"access": "ALLOW", "requireFactor": require_factor}}}]],
            "accessPolicies": [], "accessRules": []}


def value(out):
    return out["transformedResponse"]["isMFAEnabled"], out["additionalInfo"]["dataCollection"]["status"]


@pytest.mark.parametrize("mode", MODES)
def test_two_readable_two_factor_rules_beside_five_unread_is_enabled(mode):
    """The shape that regressed: 7 allowing rules, 2 require two factors, 5 use a method this code does not read."""
    out = enabled(mode, seven_rules())
    assert value(out) == (True, "success")
    assert out["additionalInfo"]["dataCollection"]["errors"] == []
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert (summary["allowRules"], summary["twoFactorRules"], summary["unreadRules"]) == (7, 2, 5)
    assert any("5 allowing sign-on rule(s)" in r and "do not change this answer" in r
               for r in out["additionalInfo"]["evaluation"]["passReasons"])


@pytest.mark.parametrize("mode", MODES)
def test_the_same_body_leaves_enforcement_not_evaluated(mode):
    """A key says only what its own evidence proves: enforcement for all users cannot be shown with five rules
    unread, so the enforcement file stays Not evaluated for exactly the body above."""
    out = enforced(mode, seven_rules())
    assert out["transformedResponse"]["isMFAEnforcedForUsers"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["evaluation"]["recommendations"] == []


@pytest.mark.parametrize("mode", MODES)
def test_one_two_factor_rule_is_enough(mode):
    assert value(enabled(mode, seven_rules(two_factor=1, unread=6))) == (True, "success")


@pytest.mark.parametrize("mode", MODES)
def test_a_single_factor_rule_does_not_undo_a_two_factor_one(mode):
    out = enabled(mode, body(("App policy", [rule("Employees"), rule("Kiosk", factor_mode="1FA"), chained("Chained")])))
    assert value(out) == (True, "success")


@pytest.mark.parametrize("mode", MODES)
def test_only_unread_rules_is_not_evaluated(mode):
    out = enabled(mode, seven_rules(two_factor=0, unread=7))
    assert value(out) == (None, "error")
    assert "7 allowing rule(s) use a verification method this check does not read" in \
        out["additionalInfo"]["dataCollection"]["errors"][0]
    assert out["additionalInfo"]["evaluation"]["recommendations"] == []


@pytest.mark.parametrize("mode", MODES)
def test_single_factor_beside_unread_without_a_two_factor_rule_is_not_evaluated(mode):
    out = enabled(mode, body(("App policy", [rule("Kiosk", factor_mode="1FA"), chained("Chained")])))
    assert value(out) == (None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_every_rule_read_and_none_requires_two_factors_is_a_measured_false(mode):
    out = enabled(mode, body(("App policy", [rule("Kiosk", factor_mode="1FA"), rule("Office", factor_mode="1FA")])))
    assert value(out) == (False, "success")
    assert out["additionalInfo"]["evaluation"]["recommendations"]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("require_factor,expected", [(True, (True, "success")), (False, (False, "success"))])
def test_classic_engine(mode, require_factor, expected):
    assert value(enabled(mode, classic(require_factor))) == expected


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("bad", [
    {"errorCode": "E0000006", "errorSummary": "You do not have permission to perform the requested action"},
    {},
    {"result": {}},
    [],
    None,
    "",
    b"\xff",
    {"accessPolicies": [policy("App policy")], "accessRules": []},
    {"accessPolicies": [policy("App policy")], "accessRules": [[]]},
    {"accessPolicies": [policy("App policy")], "accessRules": [[rule("Blocked", access="DENY")]]},
], ids=["error-envelope", "empty-object", "wrapped-empty", "list", "null", "empty-string", "bad-bytes",
        "rules-missing", "no-active-rules", "no-allowing-rule"])
def test_a_read_that_proves_nothing_is_not_evaluated(mode, bad):
    out = enabled(mode, bad)
    assert value(out) == (None, "error")
    assert out["additionalInfo"]["dataCollection"]["errors"]
    assert out["additionalInfo"]["evaluation"]["recommendations"] == []


class Poisoned(dict):
    def __getattribute__(self, name):
        raise RuntimeError("poisoned read")

    def __getitem__(self, key):
        raise RuntimeError("poisoned read")

    def __contains__(self, key):
        raise RuntimeError("poisoned read")


@pytest.mark.parametrize("mode", MODES)
def test_poisoned_body_is_not_evaluated(mode):
    out = enabled(mode, Poisoned())
    assert value(out) == (None, "error")
    assert out["additionalInfo"]["dataCollection"]["errors"][0].startswith("Transformation error")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("build", [
    lambda: seven_rules(),
    lambda: seven_rules(two_factor=0, unread=3),
    lambda: seven_rules(two_factor=3, unread=0),
    lambda: body(("App policy", [rule("Kiosk", factor_mode="1FA")])),
    lambda: body(("App policy", [rule("Employees"), rule("Kiosk", factor_mode="1FA")])),
    lambda: body(("App policy", [rule("Employees", factor_mode="")])),
    lambda: classic(True),
    lambda: classic(False),
    lambda: {},
], ids=["mixed", "unread-only", "all-two-factor", "single-only", "two-and-single", "missing-mode", "classic-on",
        "classic-off", "empty"])
def test_the_enabled_file_reads_rules_as_the_enforcement_file_does(mode, build):
    """The rule reading is duplicated across the two files. Where the enforcement file measures isMFAEnabled
    (it withholds it when isMFAEnforcedForUsers is not measured), the two files agree."""
    shared = enforced(mode, build())
    mine = enabled(mode, build())
    shared_value = shared["transformedResponse"]["isMFAEnabled"]
    if shared_value is not None:
        assert mine["transformedResponse"]["isMFAEnabled"] is shared_value
    else:
        assert mine["transformedResponse"]["isMFAEnabled"] is not False


@pytest.mark.parametrize("mode", MODES)
def test_input_is_not_mutated(mode):
    import copy
    data = seven_rules()
    before = copy.deepcopy(data)
    enabled(mode, data)
    assert data == before
