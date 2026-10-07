"""Cisco FMC firewall_transform: isFirewallEnabled from the policy assignment list. The pass fixture is the
PolicyAssignment body Cisco publishes in the FMC access control policy REST guide, placed in the list envelope the
Quick Start Guide documents (links, items, paging); the others change one field of it. The audit-log bodies are what
the definition sends this file today (getAuditLogging): they must be Not evaluated, never PASS. Every case asserts
the value AND the dataCollection status, typed, stringified, wrapped, and in the RestrictedPython replica."""
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
# The file answers exactly one criterion. The other two rows the definition points here must be
# removed or re-pointed; emitting them as None would have them compared as an answer.
ROUTED_HERE = ("isFirewallEnabled",)

DOC_ASSIGNMENT = {"type": "PolicyAssignment", "id": "policyassignmentUUID",
                  "policy": {"type": "AccessPolicy", "name": "Policy1", "id": "00505691-AED0-0ed3-0000-004294990861"},
                  "targets": [{"id": "931837d8-8cef-11ee-9dd7-82aa44a9ed90", "type": "Device", "name": "10.10.0.6"}]}


def load_plain():
    spec = importlib.util.spec_from_file_location("fmc_firewall_transform", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def coll(items, count=None):
    return {"links": {"self": "https://fmc.example.invalid/x"}, "items": items,
            "paging": {"offset": 0, "limit": 25, "count": len(items) if count is None else count, "pages": 1}}


def assignment(policy_type="AccessPolicy", targets=1, pid="p"):
    out = copy.deepcopy(DOC_ASSIGNMENT)
    out["id"] = "assign-" + pid
    out["policy"]["type"] = policy_type
    out["targets"] = out["targets"] * targets
    return out


def audit(records):
    return {"items": records, "paging": {"offset": 0, "limit": 25, "count": len(records), "pages": 1}}


LOGIN = {"id": "audit-0001", "type": "AuditRecord", "subsystem": "Login", "user": "admin", "source": "192.0.2.1",
         "time": 1735689600000, "message": "Login Success"}


class Poisoned(dict):
    def boom(self, *a, **k):
        raise RuntimeError("every read raises")
    __getitem__ = get = keys = items = values = __iter__ = __contains__ = __len__ = boom


MEASURED = [
    ("Cisco's published assignment", coll([DOC_ASSIGNMENT]), True),
    ("one of several assignments on a device", coll([assignment(targets=0, pid="1"), assignment(pid="2"),
                                                     assignment("PlatformSettingsPolicy", pid="3")]), True),
    ("an access policy assigned to no device", coll([assignment(targets=0)]), False),
    ("only non-access policies assigned", coll([assignment("FTDNatPolicy"),
                                                assignment("PlatformSettingsPolicy", pid="2")]), False),
]

NO_EVIDENCE = [
    ("audit log with a login record (was PASS)", audit([LOGIN])),
    ("empty audit log (was PASS)", audit([])),
    ("no assignments", coll([])),
    ("references only, read without expanded=true",
     coll([{"type": "PolicyAssignment", "id": "policyassignmentUUID", "name": "Policy1"}])),
    ("partial page with no access policy on a device", coll([assignment(targets=0)], count=60)),
    ("FMC error envelope", {"error": {"category": "FRAMEWORK", "messages": [{"description": "Access token invalid."}],
                                      "severity": "ERROR"}}),
    ("vendor error as response", {"vendorErrorAsResponse": {"status": 401, "message": "token expired"}}),
    ("empty dict", {}),
    ("empty string", ""),
    ("the old self-answer field and nothing else", {"isFirewallEnabled": True, "isFirewallLoggingEnabled": True}),
]


def shapes(body):
    yield body
    yield json.dumps(body)
    yield {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}


@pytest.fixture(params=["plain", "sandboxed"])
def tx(request):
    return load_plain() if request.param == "plain" else load_sandboxed()


@pytest.mark.parametrize("name,body,want", MEASURED, ids=[c[0] for c in MEASURED])
def test_measured(tx, name, body, want):
    for shape in shapes(body):
        out = tx(shape)
        assert out["additionalInfo"]["dataCollection"]["status"] == "success"
        assert out["transformedResponse"][KEY] is want


@pytest.mark.parametrize("name,body", NO_EVIDENCE, ids=[c[0] for c in NO_EVIDENCE])
def test_no_evidence_is_not_evaluated(tx, name, body):
    for shape in shapes(body):
        out = tx(shape)
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert out["additionalInfo"]["dataCollection"]["errors"]
        for k in ROUTED_HERE:
            assert out["transformedResponse"][k] is None


def test_poisoned_body_is_not_evaluated(tx):
    out = tx(Poisoned())
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    for k in ROUTED_HERE:
        assert out["transformedResponse"][k] is None
