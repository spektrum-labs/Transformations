"""Secure Score checks (every file that reads controlScores): no controlScores to read is unknown, never a measured fail.

Microsoft Graph GET /security/secureScores timed out (504) at larger tenants, and an
empty or failed read came back from these transforms as False: a red check for a
control nobody measured. Now a body that is not a Secure Score, an error object (the
Integration-Service error stub or a Graph error), an empty value list, or a score with
no controlScores returns the criterion as None with additionalInfo.dataCollection.status
"error", which Token-Service records as Not evaluated. A transformation crash reports on
that channel too. A real score still passes at 100% and fails below it.

Fixtures are synthetic. Each case runs as plain Python and in the Token-Service sandbox replica.
"""
import importlib.util
import json
import pathlib
import re

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TAG = "securescorenoevidence"

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

# Every transform in this directory that reads Secure Score controlScores, found by reading the files,
# so a new one that skips the guard fails here. These three read controlScores but are wired to other
# methods (not getRecentSecureScores); a file added to this set needs the same reason.
NOT_SECURE_SCORE_FILES = {"areadminaccountsseparate", "isadminmfaphishingresistant", "ismfaenforcedforusers"}
# Report "no data" as False with a collection error (Token-Service reads that as Not evaluated), not None.
NO_DATA_FALSE = {"ismailboxauditingenabled", "isauditlogsearchenabled"}


def _checks():
    out = {}
    for path in sorted(HERE.glob("*.py")):
        text = path.read_text()
        if path.name.startswith("test_") or "controlScores" not in text or path.stem in NOT_SECURE_SCORE_FILES:
            continue
        out[path.stem] = re.search(r'criteriaKey\s*=\s*"(\w+)"', text).group(1)
    return out


# file -> criterion key
CHECKS = _checks()
CONTROLS = ["dlp_datalossprevention", "mdo_blockmailforward", "IntegratedApps", "mdo_safeattachmentpolicy",
            "mdo_safeattachments", "mdo_autoforwardingmode", "mip_sensitivitylabelspolicies",
            "BlockLegacyAuthentication", "mdo_safelinksforemail", "exo_mailboxaudit", "mip_search_auditlog"]


def score(pct):
    return {"value": [{"createdDateTime": "2026-11-01T00:00:00Z", "currentScore": 10.0, "maxScore": 20.0,
                       "controlScores": [{"controlName": c, "scoreInPercentage": pct, "count": 5, "total": 5}
                                         for c in CONTROLS]}]}


SYNTHETIC_EMAIL = "someone@example.invalid"
NO_EVIDENCE = {
    "none": None,
    "not_a_dict": "[1, 2]",
    "empty_dict": {},
    "empty_value": {"value": []},
    "value_not_a_list": {"value": "x"},
    "score_not_a_dict": {"value": ["x"]},
    "controlScores_missing": {"value": [{"currentScore": 1.0}]},
    "controlScores_empty": {"value": [{"controlScores": []}]},
    "controlScores_null": {"value": [{"controlScores": None}]},
    "is_error_stub_504": {"error": True, "errorType": "vendor_error", "statusCode": 504,
                          "message": "Gateway Timeout for " + SYNTHETIC_EMAIL},
    "graph_error": {"error": {"code": "UnknownError", "message": "failed for " + SYNTHETIC_EMAIL}},
    "status_code_only": {"status_code": 503},
}


def load(name, mode):
    path = HERE / (name + ".py")
    if mode == "python":
        spec = importlib.util.spec_from_file_location(TAG + "_" + name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.transform
    return load_code(path.read_text(), str(path))["transform"]


def unevaluated(out):
    return out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", sorted(CHECKS))
def test_full_score_passes(name, mode):
    out = load(name, mode)(score(100.0))
    assert out["transformedResponse"][CHECKS[name]] is True
    assert not unevaluated(out)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("name", sorted(CHECKS))
def test_zero_score_is_a_measured_fail(name, mode):
    out = load(name, mode)(score(0.0))
    assert out["transformedResponse"][CHECKS[name]] is False
    assert not unevaluated(out)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("case", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("name", sorted(CHECKS))
def test_no_controlScores_is_unknown_with_a_reason(name, case, mode):
    body = NO_EVIDENCE[case]
    out = load(name, mode)(body if isinstance(body, str) else json.dumps(body))
    value = out["transformedResponse"][CHECKS[name]]
    assert value is None or (name in NO_DATA_FALSE and value is False)
    assert unevaluated(out)
    errors = out["additionalInfo"]["dataCollection"]["errors"]
    assert errors and all(isinstance(e, str) and e for e in errors)
    # The vendor's message text never reaches the reason: status or code only.
    assert SYNTHETIC_EMAIL not in json.dumps(out)


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_status_or_code_is_named(name):
    out = load(name, "python")(NO_EVIDENCE["is_error_stub_504"])
    assert "HTTP 504" in out["additionalInfo"]["dataCollection"]["errors"][0]
    out = load(name, "python")(NO_EVIDENCE["graph_error"])
    assert "UnknownError" in out["additionalInfo"]["dataCollection"]["errors"][0]


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_a_wrapped_successful_body_is_read(name):
    out = load(name, "python")({"response": score(100.0)})
    assert out["transformedResponse"][CHECKS[name]] is True


class Poisoned(dict):
    """A body whose every read raises: drives the transform down its except path."""

    def __contains__(self, key):
        raise RuntimeError("boom")

    def get(self, *a, **k):
        raise RuntimeError("boom")


def test_every_secure_score_file_is_covered():
    # The guard names these files: a silent drop in the derived list fails here.
    assert {"isurlrewriteenabled", "ismailboxauditingenabled", "isauditlogsearchenabled"} <= set(CHECKS)
    assert len(CHECKS) >= 14


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_a_crash_is_reported_as_not_evaluated(name):
    out = load(name, "python")(Poisoned(value=[]))
    assert out["transformedResponse"][CHECKS[name]] is not True
    assert unevaluated(out)
