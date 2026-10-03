"""Microsoft Purview Information Protection (Data Security): isDataClassificationEnabled,
isInformationRightsManagementEnabled.

Fixtures follow https://learn.microsoft.com/en-us/graph/api/security-informationprotection-list-sensitivitylabels?view=graph-rest-beta .
"""
import importlib.util
from pathlib import Path

import pytest


def load(name):
    spec = importlib.util.spec_from_file_location("mpip_" + name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CLASSIFY = load("isDataClassificationEnabled")
IRM = load("isInformationRightsManagementEnabled")


def label(i, active=True, protected=False):
    return {"id": "l%d" % i, "name": "Label %d" % i, "sensitivity": i, "isActive": active, "isAppliable": True,
            "contentFormats": ["file", "email"], "hasProtection": protected}


def labels(*items):
    return {"@odata.context": "https://graph.microsoft.com/beta/$metadata#security/informationProtection/sensitivityLabels",
            "value": list(items)}


def run(module, key, payload):
    out = module.transform(payload)
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


def test_active_and_protected_labels():
    body = labels(label(1), label(2, protected=True), label(3, active=False, protected=True))
    assert run(CLASSIFY, "isDataClassificationEnabled", body) == (True, "success")
    assert run(IRM, "isInformationRightsManagementEnabled", body) == (True, "success")
    out = IRM.transform(body)["transformedResponse"]
    assert (out["protectedLabelCount"], out["activeLabelCount"]) == (1, 2)


def test_labels_without_protection():
    body = labels(label(1), label(2))
    assert run(CLASSIFY, "isDataClassificationEnabled", body) == (True, "success")
    assert run(IRM, "isInformationRightsManagementEnabled", body) == (False, "success")


def test_only_inactive_labels_or_none():
    for body in (labels(label(1, active=False, protected=True)), labels()):
        assert run(CLASSIFY, "isDataClassificationEnabled", body) == (False, "success")
        assert run(IRM, "isInformationRightsManagementEnabled", body) == (False, "success")


def test_is_enabled_spelling_counts():
    body = labels({"id": "l9", "isEnabled": True, "hasProtection": True})
    assert run(IRM, "isInformationRightsManagementEnabled", body) == (True, "success")


NO_EVIDENCE = {
    "null": None,
    "empty_dict": {},
    "empty_string": "",
    "graph_403": {"error": {"code": "Forbidden", "message": "Missing InformationProtectionPolicy.Read.All"}},
    "auth_401": {"statusCode": 401, "error": "Unauthorized"},
    "unrelated": {"hello": "world"},
    "not_found_404": {"statusCode": 404, "error": "Not Found"},
    "pagination_incomplete": {"error": True, "errorType": "pagination_incomplete", "status": "Error", "statusCode": 429},
    "paged": dict(labels(label(1, protected=True)), **{"@odata.nextLink": "https://graph.microsoft.com/beta/x?$skiptoken=y"}),
}
CASES = [(CLASSIFY, "isDataClassificationEnabled"), (IRM, "isInformationRightsManagementEnabled")]


@pytest.mark.parametrize("name", sorted(NO_EVIDENCE))
@pytest.mark.parametrize("module,key", CASES, ids=[k for m, k in CASES])
def test_no_evidence_is_unevaluated(module, key, name):
    assert run(module, key, NO_EVIDENCE[name]) == (None, "error")


def test_every_transform_reports_schema_version_2_0():
    """transformedResponse envelope is the CONTRIBUTING.md schemaVersion 2.0 one, on answers and on errors."""
    import importlib.util as iu
    for path in sorted(Path(__file__).parent.glob("*.py")):
        if path.name.startswith("test_"):
            continue
        spec = iu.spec_from_file_location("schema_" + path.stem, path)
        module = iu.module_from_spec(spec)
        spec.loader.exec_module(module)
        out = module.transform({})
        assert out["additionalInfo"]["metadata"]["schemaVersion"] == "2.0", path.name
        assert set(out["additionalInfo"]) == {"dataCollection", "validation", "transformation", "evaluation", "metadata"}
