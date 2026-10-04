"""Vision One cannot see the state of some protection agents (for example those managed by Worry-Free
Business Security): eppAgent.status "unknown", componentVersion "unknownVersions" and an empty policyName.
A key that cannot read the state must say Not evaluated (None), never False/0; a measured negative still
fails. Synthetic endpoints only."""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
WF = "Trend Micro Worry-Free Business Security Services"


def mod(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def ep(name, kind="desktop", manager=WF, status="on", comp="latestVersion", policy=""):
    return {"agentGuid": name, "endpointName": name, "type": kind,
            "eppAgent": {"version": "6.7.4201", "protectionManager": manager, "status": status,
                         "componentVersion": comp, "policyName": policy}}


def verdict(name, key, items):
    out = mod(name).transform({"items": items, "count": len(items), "totalCount": len(items)})
    return out["transformedResponse"][key]


def test_configured_all_worry_free_without_policy_is_not_evaluated():
    assert verdict("iseppconfigured", "isEPPConfigured", [ep("a"), ep("b")]) is None


def test_configured_measures_only_visible_agents():
    items = [ep("a"), ep("b", manager="Trend Micro Apex One", policy="Std"), ep("c", manager="Trend Micro Apex One")]
    assert verdict("iseppconfigured", "isEPPConfigured", items) == 50


def test_critical_systems_unknown_server_is_not_evaluated():
    items = [ep("s1", kind="server", status="on"), ep("s2", kind="server", status="unknown")]
    assert verdict("iseppenabledforcriticalsystems", "isEPPEnabledForCriticalSystems", items) is None


def test_critical_systems_measured_off_still_fails():
    items = [ep("s1", kind="server", status="off"), ep("s2", kind="server", status="unknown")]
    assert verdict("iseppenabledforcriticalsystems", "isEPPEnabledForCriticalSystems", items) is False


def test_critical_systems_all_on_passes():
    assert verdict("iseppenabledforcriticalsystems", "isEPPEnabledForCriticalSystems", [ep("s1", kind="server")]) is True


def test_signature_unknown_versions_is_not_evaluated():
    items = [ep("a"), ep("b", comp="unknownVersions")]
    assert verdict("issignatureuptodate", "isSignatureUpToDate", items) is None


def test_signature_outdated_still_fails():
    items = [ep("a", comp="outdatedVersion"), ep("b", comp="unknownVersions")]
    assert verdict("issignatureuptodate", "isSignatureUpToDate", items) is False


def test_signature_all_latest_passes():
    assert verdict("issignatureuptodate", "isSignatureUpToDate", [ep("a"), ep("b", comp="controlledLatestVersion")]) is True
