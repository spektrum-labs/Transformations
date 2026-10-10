"""Microsoft 365 One-Click: isOWAOfflineAccessDisabled from getOwaMailboxPolicies (certificate-auth Exchange
Online Lambda, scripts/GetOwaMailboxPolicies-Cert.ps1). SYNTHETIC fixtures only: policy names, domains and counts
are made up.

The body is the Lambda's answer, {"Success", "Output", "Error"}, with Output as the script prints it. Each case
also runs Token-Service-wrapped, stringified (Token-Service stores every leaf as a string), with Output as a JSON
string, and in the RestrictedPython replica.
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NAME = "isowaofflineaccessdisabled"
KEY = "isOWAOfflineAccessDisabled"
TAG = "owaoffline"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(mode):
    path = HERE / (NAME + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + NAME, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def run(body, mode):
    out = load(mode)(copy.deepcopy(body))
    return out["transformedResponse"].get(KEY), out["additionalInfo"]["dataCollection"]["status"], out


def policy(name, allow="NoComputers", default=False):
    return {"Name": name, "Identity": name, "IsDefault": default, "AllowOfflineOn": allow}


def output(policies, by_policy=None, unassigned=0, complete=True, count=None, error=""):
    by_policy = by_policy if by_policy is not None else {}
    enabled = unassigned + sum(by_policy.values())
    return {"collectedAt": "2026-10-06T20:00:00.0000000+00:00", "success": True,
            "organizationDomain": "contoso.example", "policyCount": len(policies) if count is None else count,
            "policies": policies,
            "usage": {"complete": complete, "owaEnabledMailboxCount": enabled if complete else 0,
                      "unassignedMailboxCount": unassigned if complete else 0,
                      "byPolicy": by_policy if complete else {}, "error": error}}


def lam(out):
    return {"Success": True, "Output": out, "Error": ""}


def ts(body):
    return {"data": body, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def stringify(v):
    if isinstance(v, dict):
        return {k: stringify(x) for k, x in v.items()}
    if isinstance(v, list):
        return [stringify(x) for x in v]
    return str(v)


SHAPES = [lambda o: lam(o), lambda o: ts(lam(o)), lambda o: ts(stringify(lam(o))),
          lambda o: lam(json.dumps(o)), lambda o: ts(json.dumps(lam(o))), lambda o: o,
          lambda o: {"apiResponse": lam(o)}]

DEFAULT = "OwaMailboxPolicy-Default"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", SHAPES)
def test_every_policy_no_computers_is_true_even_without_usage(mode, shape):
    pols = [policy(DEFAULT, default=True), policy("Contractors")]
    for out in (output(pols, {"Contractors": 4}, unassigned=10), output(pols, complete=False, error="timeout")):
        v, dc, res = run(shape(out), mode)
        assert (v, dc) == (True, "success")
        assert res["transformedResponse"]["policiesAllowingOffline"] == 0


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", SHAPES)
@pytest.mark.parametrize("allow", ["AllComputers", "PrivateComputersOnly", "allcomputers"])
def test_default_policy_in_use_allowing_offline_is_false(mode, shape, allow):
    pols = [policy(DEFAULT, allow=allow, default=True), policy("Executives")]
    v, dc, res = run(shape(output(pols, {"Executives": 3}, unassigned=20)), mode)
    assert (v, dc) == (False, "success")
    assert DEFAULT in res["additionalInfo"]["evaluation"]["failReasons"][0]
    assert res["additionalInfo"]["dataCollection"]["errors"] == []
    assert res["transformedResponse"]["inUsePoliciesAllowingOffline"] == 1


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", SHAPES)
def test_assigned_policy_in_use_allowing_offline_is_false(mode, shape):
    pols = [policy(DEFAULT, default=True), policy("Remote", allow="AllComputers")]
    v, dc, res = run(shape(output(pols, {"Remote": 1}, unassigned=5)), mode)
    assert (v, dc) == (False, "success")
    assert "Remote (AllComputers)" in res["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("shape", SHAPES)
def test_unused_policy_allowing_offline_does_not_fail(mode, shape):
    pols = [policy(DEFAULT, allow="AllComputers", default=True), policy("Locked")]
    v, dc, res = run(shape(output(pols, {"Locked": 12, "locked": 0})), mode)   # nobody unassigned, so default unused
    assert (v, dc) == (True, "success")
    assert res["transformedResponse"]["policiesInUse"] == 1


@pytest.mark.parametrize("mode", MODES)
def test_policy_matched_by_identity_or_case(mode):
    pols = [policy(DEFAULT, default=True), dict(policy("Remote", allow="AllComputers"), Identity="Remote-Id")]
    assert run(lam(output(pols, {"remote-id": 2})), mode)[:2] == (False, "success")
    assert run(lam(output(pols, {"REMOTE": 2})), mode)[:2] == (False, "success")


NO_EVIDENCE = [None, {}, [], "", "{}", "not json",
               {"Success": True, "Output": "", "Error": ""},
               {"Success": True, "Output": "plain text output", "Error": ""},
               {"Success": False, "Output": "", "Error": "pwsh exited 1"},
               {"error": "ScriptPath not allowed"}, {"error": "Internal error"},
               {"statusCode": 403, "body": "Forbidden"},
               {"Success": True, "Error": "", "Output": {"collectedAt": "x", "success": False,
                                                          "organizationDomain": None,
                                                          "PSError": "Failed to connect to Exchange Online: UnAuthorized"}}]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_unevaluated(mode, body):
    for b in (body, ts(body)):
        v, dc, res = run(b, mode)
        assert (v, dc) == (None, "error"), b
        assert res["additionalInfo"]["dataCollection"]["errors"]


BAD = "Remote"


def bad_pols():
    return [policy(DEFAULT, default=True), policy(BAD, allow="AllComputers")]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("out", [
    output([]),                                                        # empty policy list
    output([policy(DEFAULT, default=True)], count=2),                  # partial policy list
    dict(output([policy(DEFAULT, default=True)]), policyCount=None),   # no count to prove completeness
    output([policy("", default=True)]),                                # policy without a name
    output([policy(DEFAULT, allow="2", default=True)]),                # numeric enum, not a name
    output([policy(DEFAULT, allow="", default=True)]),
    dict(output([policy(DEFAULT, default=True)]), success=False),
    dict(output([policy(DEFAULT, default=True)]), policies="none"),
    output(bad_pols(), complete=False, error="Mailbox policy assignments could not be read: timeout"),
    output(bad_pols(), {"Ghost": 3}, unassigned=1),                    # usage names an unknown policy
    output(bad_pols(), {}, unassigned=0),                              # no OWA-enabled mailbox
    output([policy("A"), policy(BAD, allow="AllComputers")], {"A": 1}, unassigned=2),   # no default policy
])
def test_partial_or_unprovable_is_unevaluated(mode, out):
    for b in (lam(out), ts(stringify(lam(out)))):
        v, dc, res = run(b, mode)
        assert (v, dc) == (None, "error"), out
        assert res["additionalInfo"]["dataCollection"]["errors"]


@pytest.mark.parametrize("mode", MODES)
def test_usage_that_does_not_add_up_is_unevaluated(mode):
    out = output(bad_pols(), {BAD: 2}, unassigned=3)
    out["usage"]["owaEnabledMailboxCount"] = 9
    assert run(lam(out), mode)[:2] == (None, "error")


@pytest.mark.parametrize("mode", MODES)
def test_incomplete_usage_names_the_policies_that_allow_offline(mode):
    v, dc, res = run(lam(output(bad_pols(), complete=False, error="timeout")), mode)
    assert (v, dc) == (None, "error")
    assert BAD in res["additionalInfo"]["dataCollection"]["errors"][0]


class Poisoned(dict):
    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


@pytest.mark.parametrize("mode", MODES)
def test_except_path_is_unevaluated(mode):
    res = load(mode)(Poisoned())
    assert res["transformedResponse"][KEY] is None
    assert res["additionalInfo"]["dataCollection"]["status"] == "error"


def test_key_is_new_in_the_tree():
    hits = [p for p in (ROOT / "safeguards").rglob("*.py")
            if p.name != NAME + ".py" and not p.name.startswith("test_") and KEY in p.read_text(errors="ignore")]
    assert hits == []
