"""Amazon Cognito isStrongAuthRequired (GetUserPoolMfaConfig).

Fixtures in fixtures/ are built from the vendor's documented response shape (AWS API reference,
GetUserPoolMfaConfig) with every name, id and account replaced (example.com, 111111111111).
No customer tenant was read. Each case runs twice: imported as plain Python, and compiled and
run in the production RestrictedPython sandbox (tools/restricted_sandbox.py) when RestrictedPython
is installed."""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MODULE = "isstrongauthrequired"
KEY = "isStrongAuthRequired"

NO_EVIDENCE = [
    {}, None, "{}", "", [], "   ", {"hello": "world"}, {"foo": {"bar": [1, 2, 3]}},
    {"error": {"type": "authentication_error"}},
    {"statusCode": 401, "error": "Unauthorized"}, {"statusCode": 403, "error": "Forbidden"},
    {"error": True, "message": "upstream timeout"},
    {"__type": "AccessDeniedException", "Message": "User is not authorized to perform: cognito-idp:GetUserPoolMfaConfig"},
    {"__type": "com.amazonaws.cognito.identity.idp.model#ResourceNotFoundException", "message": "User pool us-east-1_EXAMPLE does not exist."},
    {"__type": "UnrecognizedClientException", "message": "The security token included in the request is invalid."},
    {"__type": "NotAuthorizedException", "message": "Not authorized", "MfaConfiguration": "ON"},
    {"Output": {"__type": "com.amazon.coral.service#UnknownOperationException"}, "Version": "1.0"},
    {"apiResponse": {"__type": "InvalidParameterException", "message": "bad pool id"}},
]


def plain(name):
    spec = importlib.util.spec_from_file_location("cognito_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def sandboxed(name):
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, str(ROOT / "tools"))
    import restricted_sandbox
    return restricted_sandbox.load((HERE / (name + ".py")).read_text())["transform"]


LOADERS = [plain, sandboxed]
IDS = ["plain", "sandbox"]


def fixture(name):
    return json.loads((HERE / "fixtures" / name).read_text())


def verdict(out):
    return out["transformedResponse"][KEY], out["additionalInfo"]["dataCollection"]["status"]


CASES = [
    ("mfa_required.json", True),
    ("mfa_optional.json", False),
    ("mfa_off.json", False),
]


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
@pytest.mark.parametrize("fixture_name,expected", CASES)
def test_fixture(loader, fixture_name, expected):
    value, status = verdict(loader(MODULE)(fixture(fixture_name)))
    assert value is expected
    assert status == "success"


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
@pytest.mark.parametrize("body", NO_EVIDENCE, ids=[str(i) for i in range(len(NO_EVIDENCE))])
def test_no_evidence_is_not_evaluated(loader, body):
    value, status = verdict(loader(MODULE)(body))
    assert value is None and status == "error"


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
@pytest.mark.parametrize("bad", ["on", "Off", "ENFORCED", "REQUIRED", "", None, 1, True, ["ON"], {"ON": 1}],
                         ids=["lower-on", "mixed-off", "enforced", "required", "empty", "null", "one", "true",
                              "list", "dict"])
def test_unknown_mfa_configuration_is_not_evaluated(loader, bad):
    body = fixture("mfa_required.json")
    body["MfaConfiguration"] = bad
    value, status = verdict(loader(MODULE)(body))
    assert value is None and status == "error"


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
def test_missing_mfa_configuration_is_not_evaluated(loader):
    body = fixture("mfa_required.json")
    del body["MfaConfiguration"]
    value, status = verdict(loader(MODULE)(body))
    assert value is None and status == "error"


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
@pytest.mark.parametrize("mode,expected", [("ON", True), ("OPTIONAL", False), ("OFF", False)])
def test_only_the_mfa_setting_decides(loader, mode, expected):
    for name in ("mfa_required.json", "mfa_optional.json", "mfa_off.json"):
        body = fixture(name)
        body["MfaConfiguration"] = mode
        assert verdict(loader(MODULE)(body))[0] is expected


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
@pytest.mark.parametrize("fixture_name,expected", CASES)
def test_json_string_and_wrapped_input_match_dict(loader, fixture_name, expected):
    raw = (HERE / "fixtures" / fixture_name).read_text()
    assert verdict(loader(MODULE)(raw))[0] is expected
    assert verdict(loader(MODULE)(raw.encode("utf-8")))[0] is expected
    for wrapper in ("apiResponse", "response", "result", "api_response"):
        assert verdict(loader(MODULE)({wrapper: json.loads(raw)}))[0] is expected
    assert verdict(loader(MODULE)({"apiResponse": {"result": json.loads(raw)}}))[0] is expected


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
def test_factors_are_reported_but_do_not_decide(loader):
    on = loader(MODULE)(fixture("mfa_required.json"))["transformedResponse"]
    assert on["factorsConfigured"] == ["TOTP", "SMS"]
    off = loader(MODULE)(fixture("mfa_off.json"))["transformedResponse"]
    assert off["factorsConfigured"] == []
    # a pool that is ON with no factor listed is still ON: the API setting is the evidence
    bare = loader(MODULE)({"MfaConfiguration": "ON"})
    assert verdict(bare) == (True, "success")


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
def test_result_is_boolean_or_none_only(loader):
    for name, expected in CASES:
        value = loader(MODULE)(fixture(name))["transformedResponse"][KEY]
        assert isinstance(value, bool)
    for body in NO_EVIDENCE:
        value = loader(MODULE)(body)["transformedResponse"][KEY]
        assert value is None


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
def test_input_is_not_modified(loader):
    body = fixture("mfa_optional.json")
    before = copy.deepcopy(body)
    loader(MODULE)(body)
    assert body == before


@pytest.mark.parametrize("loader", LOADERS, ids=IDS)
def test_poisoned_body_is_not_evaluated(loader):
    class Poison(dict):
        def get(self, *args, **kwargs):
            raise RuntimeError("boom")
    out = loader(MODULE)(Poison(MfaConfiguration="ON"))
    assert verdict(out) == (None, "error")
