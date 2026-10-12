"""A Trend Vision One value the vendor does not expose says so with a machine-readable code (12 Oct 2026).

Vision One does not receive policy, status, isolation or component version for agents managed by
Trend Micro Worry-Free Business Security. Those checks already answer None (Not evaluated) with a
dataCollection error, but the error was prose only, so a triage tool could not tell "the vendor does
not expose this" from a broken call and printed "instrument the failure". The dataCollection block
now carries errorCode "VENDOR_DATA_NOT_EXPOSED" in exactly that case, and in no other. The value
stays None. Synthetic endpoints only."""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
WF = "Trend Micro Worry-Free Business Security Services"
CODE = "VENDOR_DATA_NOT_EXPOSED"


def mod(name):
    spec = importlib.util.spec_from_file_location("tmv1_vdne_" + name, HERE / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ep(name, kind="desktop", manager=WF, status="on", comp="latestVersion", policy="", isolation=None):
    e = {"agentGuid": name, "endpointName": name, "type": kind,
         "eppAgent": {"version": "6.7.4201", "protectionManager": manager, "status": status,
                      "componentVersion": comp, "policyName": policy}}
    if isolation is not None:
        e["isolationStatus"] = isolation
    return e


def run(name, items):
    return mod(name).transform({"items": items, "count": len(items), "totalCount": len(items)})


def collection(out):
    return out["additionalInfo"]["dataCollection"]


# (file, criteria key, endpoints whose value Vision One cannot see)
HIDDEN = [
    ("iseppconfigured", "isEPPConfigured", [ep("a"), ep("b")]),
    ("iseppenabledforcriticalsystems", "isEPPEnabledForCriticalSystems",
     [ep("s1", kind="server", status="on"), ep("s2", kind="server", status="unknown")]),
    ("isolatedendpointcount", "isolatedEndpointCount", [ep("a"), ep("b", isolation="off")]),
    ("contentversiondriftcount", "contentVersionDriftCount", [ep("a"), ep("b", comp="unknownVersions")]),
    ("issignatureuptodate", "isSignatureUpToDate", [ep("a"), ep("b", comp="unknownVersions")]),
    ("endpointoperationalstatusunprotectedcount", "endpointOperationalStatusUnprotectedCount",
     [ep("a"), ep("b", status="unknown")]),
]


def test_hidden_value_is_none_with_the_vendor_code():
    for name, key, items in HIDDEN:
        out = run(name, items)
        assert out["transformedResponse"][key] is None, name
        dc = collection(out)
        assert dc["status"] == "error" and dc["errors"], name
        assert dc["errorCode"] == CODE, name


# Measured verdicts: a value, no error, so no code.
MEASURED = [
    ("iseppconfigured", [ep("b", manager="Trend Micro Apex One", policy="Std")]),
    ("iseppenabledforcriticalsystems", [ep("s1", kind="server")]),
    ("isolatedendpointcount", [ep("a", isolation="off")]),
    ("contentversiondriftcount", [ep("a")]),
    ("issignatureuptodate", [ep("a")]),
    ("endpointoperationalstatusunprotectedcount", [ep("a")]),
]


def test_measured_verdicts_carry_no_code():
    for name, items in MEASURED:
        dc = collection(run(name, items))
        assert dc["status"] == "success" and "errorCode" not in dc, name


# A measured failure beside hidden agents is still a value, so no code.
def test_measured_failure_beside_hidden_agents_carries_no_code():
    cases = [
        ("iseppenabledforcriticalsystems", [ep("s1", kind="server", status="off"), ep("s2", kind="server", status="unknown")]),
        ("issignatureuptodate", [ep("a", comp="outdatedVersion"), ep("b", comp="unknownVersions")]),
    ]
    for name, items in cases:
        dc = collection(run(name, items))
        assert dc["status"] == "success" and "errorCode" not in dc, name


# None for a different reason is not "the vendor does not expose it": no code.
def test_other_none_reasons_carry_no_code():
    for name, key, items in HIDDEN:
        # an error body from the API
        bad = mod(name).transform({"error": {"code": "AccessDenied", "message": "no"}})
        assert collection(bad)["status"] == "error", name
        assert "errorCode" not in collection(bad), name
        # an empty endpoint list
        empty = run(name, [])
        assert "errorCode" not in collection(empty), name
    # sensor-only endpoints (no installed agent) leave nothing to measure; that is not Worry-Free
    placeholder = {"agentGuid": "p", "endpointName": "p", "type": "desktop", "eppAgent": {"status": "off"}}
    out = run("contentversiondriftcount", [placeholder])
    assert out["transformedResponse"]["contentVersionDriftCount"] is None
    assert "errorCode" not in collection(out)
