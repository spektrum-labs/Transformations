"""Cisco FMC firewall_transform: a further page of policy assignments is a partial read.

The FMC list body carries paging {"offset", "limit", "count", "pages", "next"}. The file compared only count with the
items it was given, so a body that said it had a second page (pages above one, a next link, an offset above zero, a
count or page total that cannot be read) and gave no count read as a whole list: an access policy that sits on the
unread page was reported as "none assigned", a False. A "no access policy on a device" False now reads None when the
list may be only part of it; an access policy on a device that was read still proves True. The file emits one key,
isFirewallEnabled, on every path. Synthetic data only."""
import copy
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
FILE = os.path.join(HERE, "firewall_transform.py")
KEY = "isFirewallEnabled"

DOC_ASSIGNMENT = {"type": "PolicyAssignment", "id": "policyassignmentUUID",
                  "policy": {"type": "AccessPolicy", "name": "Policy1", "id": "00505691-AED0-0ed3-0000-004294990861"},
                  "targets": [{"id": "931837d8-8cef-11ee-9dd7-82aa44a9ed90", "type": "Device", "name": "10.10.0.6"}]}


def load_plain():
    spec = importlib.util.spec_from_file_location("fmc_firewall_paging", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


@pytest.fixture(params=["plain", "sandboxed"])
def tx(request):
    return load_plain() if request.param == "plain" else load_sandboxed()


def assignment(targets=1, policy_type="AccessPolicy", pid="p"):
    out = copy.deepcopy(DOC_ASSIGNMENT)
    out["id"] = "assign-" + pid
    out["policy"]["type"] = policy_type
    out["targets"] = out["targets"] * targets
    return out


def listing(items, paging):
    return {"links": {"self": "https://fmc.example.invalid/x"}, "items": items, "paging": paging}


def none_on_a_device(paging):
    """One access policy assigned to no device: a complete read of this reads False."""
    return listing([assignment(targets=0)], paging)


def shapes(body):
    yield body
    yield json.dumps(body)
    yield {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}


def collection(out):
    return out["additionalInfo"]["dataCollection"]


COMPLETE = [
    ("one page", {"offset": 0, "limit": 25, "count": 1, "pages": 1}),
    ("no paging counts at all", {}),
    ("pages above one but the count equals the items read (a joined body)", {"offset": 0, "limit": 25, "count": 1, "pages": 3}),
    ("offset as text zero", {"offset": "0", "limit": 25, "count": 1, "pages": 1}),
    ("next empty list", {"offset": 0, "count": 1, "pages": 1, "next": []}),
    ("next null", {"offset": 0, "count": 1, "pages": 1, "next": None}),
    ("next empty text", {"offset": 0, "count": 1, "pages": 1, "next": ""}),
    ("next stringified null", {"offset": 0, "count": 1, "pages": 1, "next": "None"}),
    ("pages null", {"offset": 0, "count": 1, "pages": None}),
    ("pages empty text", {"offset": 0, "count": 1, "pages": ""}),
    ("count and pages as text", {"offset": "0", "limit": "25", "count": "1", "pages": "1"}),
]

PARTIAL = [
    ("pages above one and no count", {"offset": 0, "limit": 25, "pages": 2}),
    ("pages above one and a null count", {"offset": 0, "limit": 25, "count": None, "pages": 2}),
    ("pages as text above one and no count", {"offset": 0, "limit": 25, "pages": "3"}),
    ("a next link as a list", {"offset": 0, "limit": 25, "count": 1, "pages": 1,
                               "next": ["https://fmc.example.invalid/api/x?offset=25&limit=25"]}),
    ("a next link as text", {"offset": 0, "limit": 25, "count": 1, "pages": 1,
                             "next": "https://fmc.example.invalid/api/x?offset=25&limit=25"}),
    ("an offset above zero", {"offset": 25, "limit": 25, "count": 1, "pages": 1}),
    ("an offset as text above zero", {"offset": "25", "limit": 25, "count": 1, "pages": 1}),
    ("a page total that cannot be read", {"offset": 0, "limit": 25, "count": 1, "pages": "many"}),
    ("a page total that is a boolean", {"offset": 0, "limit": 25, "count": 1, "pages": True}),
    ("a count that cannot be read", {"offset": 0, "limit": 25, "count": "many", "pages": 1}),
    ("an offset that cannot be read", {"offset": "later", "limit": 25, "count": 1, "pages": 1}),
    ("a count above the items read (as before)", {"offset": 0, "limit": 25, "count": 60, "pages": 3}),
    ("more pages than the count explains", {"offset": 0, "limit": 25, "count": 40, "pages": 2}),
]


PAGING_NOT_AN_OBJECT_PARTIAL = [("text", "page 1 of 2"), ("a number", 2), ("true", True), ("a list", []), ("a non-empty list", ["x"])]
PAGING_NOT_AN_OBJECT_COMPLETE = [("null", None), ("empty text", ""), ("stringified null", "None"), ("false", False)]


@pytest.mark.parametrize("name,paging", PAGING_NOT_AN_OBJECT_PARTIAL, ids=[c[0] for c in PAGING_NOT_AN_OBJECT_PARTIAL])
def test_a_paging_field_that_is_not_an_object_is_partial(tx, name, paging):
    for shape in shapes(none_on_a_device(paging)):
        out = tx(shape)
        assert collection(out)["status"] == "error"
        assert out["transformedResponse"][KEY] is None


@pytest.mark.parametrize("name,paging", PAGING_NOT_AN_OBJECT_COMPLETE, ids=[c[0] for c in PAGING_NOT_AN_OBJECT_COMPLETE])
def test_an_absent_paging_field_is_a_complete_read(tx, name, paging):
    for shape in shapes(none_on_a_device(paging)):
        out = tx(shape)
        assert collection(out)["status"] == "success"
        assert out["transformedResponse"][KEY] is False


def test_a_body_with_no_paging_key_is_a_complete_read(tx):
    body = {"items": [assignment(targets=0)]}
    for shape in shapes(body):
        out = tx(shape)
        assert collection(out)["status"] == "success"
        assert out["transformedResponse"][KEY] is False


@pytest.mark.parametrize("name,paging", COMPLETE, ids=[c[0] for c in COMPLETE])
def test_a_complete_read_keeps_its_false(tx, name, paging):
    for shape in shapes(none_on_a_device(paging)):
        out = tx(shape)
        assert collection(out)["status"] == "success", collection(out)
        assert out["transformedResponse"][KEY] is False


@pytest.mark.parametrize("name,paging", PARTIAL, ids=[c[0] for c in PARTIAL])
def test_a_further_page_makes_a_none_assigned_false_not_evaluated(tx, name, paging):
    for shape in shapes(none_on_a_device(paging)):
        out = tx(shape)
        assert collection(out)["status"] == "error"
        assert collection(out)["errors"]
        assert out["transformedResponse"][KEY] is None


@pytest.mark.parametrize("name,paging", PARTIAL, ids=[c[0] for c in PARTIAL])
def test_a_further_page_does_not_undo_an_access_policy_that_was_read(tx, name, paging):
    for shape in shapes(listing([assignment(targets=0, pid="1"), assignment(pid="2")], paging)):
        out = tx(shape)
        assert collection(out)["status"] == "success"
        assert out["transformedResponse"][KEY] is True


def test_only_assignments_of_other_policies_on_a_further_page_is_not_evaluated(tx):
    body = listing([assignment(policy_type="FTDNatPolicy", pid="1"), assignment(policy_type="PlatformSettingsPolicy", pid="2")],
                   {"offset": 0, "limit": 2, "count": 2, "pages": 1, "next": ["https://fmc.example.invalid/api/x?offset=2"]})
    for shape in shapes(body):
        out = tx(shape)
        assert collection(out)["status"] == "error"
        assert out["transformedResponse"][KEY] is None


# The file answers exactly one criterion. It must not emit the other two rows the definition points at it, on any path.
EVERY_PATH = [
    ("measured true", listing([assignment()], {"offset": 0, "count": 1, "pages": 1})),
    ("measured false", none_on_a_device({"offset": 0, "count": 1, "pages": 1})),
    ("partial", none_on_a_device({"offset": 0, "pages": 2})),
    ("no assignments", listing([], {"offset": 0, "count": 0, "pages": 1})),
    ("error envelope", {"error": {"category": "FRAMEWORK", "messages": [{"description": "Access token invalid."}]}}),
    ("empty", {}),
    ("not a body", "not json"),
]


@pytest.mark.parametrize("name,body", EVERY_PATH, ids=[c[0] for c in EVERY_PATH])
def test_isfirewallenabled_is_the_only_key_emitted(tx, name, body):
    for shape in shapes(body):
        assert list(tx(shape)["transformedResponse"].keys()) == [KEY]
