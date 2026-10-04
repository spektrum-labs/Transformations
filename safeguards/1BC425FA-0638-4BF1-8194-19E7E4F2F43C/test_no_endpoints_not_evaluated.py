"""Sophos MDR endpoint-list keys: an empty endpoint list is Not evaluated, never a fail.

The read returns {"items": [], "pages": {...}} when the tenant has no endpoints. There is
nothing to measure, so isBehavioralMonitoringValid, isRemovableMediaControlled and
isPatchManagementEnabled / isPatchManagementValid now read None with "no endpoints returned".
A populated list and an explicit verdict key keep their earlier readings. Synthetic bodies only.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent
EMPTY = {"items": [], "pages": {"size": "500", "maxSize": "500", "nextKey": "None"}}
POPULATED = {"items": [{"id": "ep-1", "type": "computer", "health": {"overall": "good"}}],
             "pages": {"size": "500", "maxSize": "500"}}
FILES = [("isbehavioralmonitoringvalid.py", ["isBehavioralMonitoringValid"]),
         ("isremovablemediacontrolled.py", ["isRemovableMediaControlled"]),
         ("ispatchmanagementenabled.py", ["isPatchManagementEnabled", "isPatchManagementValid"])]


def run(name, body):
    spec = importlib.util.spec_from_file_location(name[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


@pytest.mark.parametrize("name,keys", FILES)
@pytest.mark.parametrize("body", [EMPTY, [], {"items": []}])
def test_no_endpoints_is_not_evaluated(name, keys, body):
    out = run(name, body)
    for key in keys:
        assert out["transformedResponse"][key] is None
    assert "no endpoints returned" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("name,keys", FILES)
def test_populated_list_unchanged(name, keys):
    out = run(name, POPULATED)
    for key in keys:
        assert out["transformedResponse"][key] is True


@pytest.mark.parametrize("name,keys", FILES)
def test_explicit_false_still_fails(name, keys):
    body = dict(EMPTY)
    for key in keys:
        body[key] = False
    out = run(name, body)
    for key in keys:
        assert out["transformedResponse"][key] is False


@pytest.mark.parametrize("name,keys", FILES)
def test_error_body_is_never_true(name, keys):
    out = run(name, {"error": "Unauthorized"})
    for key in keys:
        assert out["transformedResponse"][key] is not True
