"""isTamperProtectionEnabled / isRealTimeProtectionEnabled read the right secure-configuration ids.

scid-2003 is tamper protection and scid-2012 is real-time protection (Microsoft's Defender agent-health hunting
query). scid-2010 (Defender Antivirus on) and scid-2011 (definitions up to date) are not evidence for either and
read Not evaluated, so a method still querying the old ids can never pass or fail these checks. Synthetic rows.
"""
import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load():
    spec = importlib.util.spec_from_file_location("scid_ids", os.path.join(HERE, "microsoft_endpoint_scid_compliance.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def hunting(rows):
    return {"Schema": [{"Name": "ConfigurationId", "Type": "String"}], "Results": rows}


def row(scid, compliant, applicable=1, device="d1"):
    return {"DeviceId": device, "DeviceName": device, "ConfigurationId": scid, "IsCompliant": compliant,
            "IsApplicable": applicable}


def test_tamper_protection_reads_scid_2003():
    out = load()(hunting([row("scid-2003", 1), row("scid-2003", 0, device="d2")]))
    assert out["transformedResponse"]["isTamperProtectionEnabled"] is False
    assert out["transformedResponse"]["tamperProtectionCompliancePercentage"] == 50
    out = load()(hunting([row("scid-2003", 1), row("scid-2003", 1, device="d2")]))
    assert out["transformedResponse"]["isTamperProtectionEnabled"] is True


def test_real_time_protection_reads_scid_2012():
    out = load()(hunting([row("scid-2012", "1"), row("scid-2012", "0", device="d2")]))
    assert out["transformedResponse"]["isRealTimeProtectionEnabled"] is False
    out = load()(hunting([row("scid-2012", True)]))
    assert out["transformedResponse"]["isRealTimeProtectionEnabled"] is True


def test_old_ids_are_not_evidence():
    for scid in ("scid-2010", "scid-2011"):
        out = load()(hunting([row(scid, 1), row(scid, 1, device="d2")]))
        assert out["transformedResponse"]["isTamperProtectionEnabled"] is None
        assert out["transformedResponse"]["isRealTimeProtectionEnabled"] is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert "scid-2003" in out["additionalInfo"]["dataCollection"]["errors"][0]


def load_legacy(name):
    spec = importlib.util.spec_from_file_location("legacy_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def test_legacy_files_refuse_the_retired_ids_and_read_the_right_ones():
    tamper = load_legacy("istamperprotectionenabled")
    rtp = load_legacy("isrealtimeprotectionenabled")
    out = tamper(hunting([row("scid-2010", 1)]))
    assert out["transformedResponse"]["isTamperProtectionEnabled"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    out = rtp(hunting([row("scid-2011", 1)]))
    assert out["transformedResponse"]["isRealTimeProtectionEnabled"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert tamper(hunting([row("scid-2003", 1)]))["transformedResponse"]["isTamperProtectionEnabled"] is True
    assert rtp(hunting([row("scid-2012", 1)]))["transformedResponse"]["isRealTimeProtectionEnabled"] is True


def test_legacy_guard_covers_bare_lists_and_any_other_id():
    tamper = load_legacy("istamperprotectionenabled")
    rtp = load_legacy("isrealtimeprotectionenabled")
    assert tamper([row("scid-2010", 1)])["transformedResponse"]["isTamperProtectionEnabled"] is None
    assert rtp([row("scid-2011", 1)])["transformedResponse"]["isRealTimeProtectionEnabled"] is None
    assert tamper(hunting([row("scid-2012", 1)]))["transformedResponse"]["isTamperProtectionEnabled"] is None
    assert rtp(hunting([row("scid-2003", 1)]))["transformedResponse"]["isRealTimeProtectionEnabled"] is None
    assert tamper([row("scid-2003", 1)])["transformedResponse"]["isTamperProtectionEnabled"] is True


def test_legacy_guard_refuses_hunting_rows_without_an_id():
    tamper = load_legacy("istamperprotectionenabled")
    r = row("scid-2003", 1)
    del r["ConfigurationId"]
    assert tamper(hunting([r]))["transformedResponse"]["isTamperProtectionEnabled"] is None


# ---- an unreadable tamper state is Not evaluated, never a fail

def not_evaluated(out, key):
    assert out["transformedResponse"][key] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"]


def test_oneclick_null_tamper_state_is_not_evaluated():
    for state in (None, "None", ""):
        out = load()(hunting([row("scid-2003", state), row("scid-2003", 1, device="d2")]))
        not_evaluated(out, "isTamperProtectionEnabled")
        assert out["transformedResponse"]["tamperProtectionUnreadableDevices"] == 1
    r = row("scid-2003", 1)
    del r["IsCompliant"]
    not_evaluated(load()(hunting([r])), "isTamperProtectionEnabled")


def test_oneclick_readable_non_compliant_still_fails_beside_a_null():
    out = load()(hunting([row("scid-2003", None), row("scid-2003", 0, device="d2"), row("scid-2003", 1, device="d3")]))
    assert out["transformedResponse"]["isTamperProtectionEnabled"] is False
    assert out["transformedResponse"]["tamperProtectionCompliancePercentage"] == 50
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_legacy_null_tamper_state_is_not_evaluated():
    tamper = load_legacy("istamperprotectionenabled")
    not_evaluated(tamper(hunting([row("scid-2003", None)])), "isTamperProtectionEnabled")
    not_evaluated(tamper(hunting([row("scid-2003", "None"), row("scid-2003", None, device="d2")])),
                  "isTamperProtectionEnabled")
    not_evaluated(tamper({"value": [{"computerDnsName": "host-a", "isTamperProtected": None}]}),
                  "isTamperProtectionEnabled")
    not_evaluated(tamper({"value": [{"computerDnsName": "host-a"}]}), "isTamperProtectionEnabled")


def test_legacy_empty_or_error_body_is_not_evaluated():
    tamper = load_legacy("istamperprotectionenabled")
    for body in ({}, hunting([]), {"value": []}, {"error": {"code": "Forbidden", "message": "denied"}}, "not json"):
        not_evaluated(tamper(body), "isTamperProtectionEnabled")


def test_legacy_readable_states_still_decide():
    tamper = load_legacy("istamperprotectionenabled")
    out = tamper(hunting([row("scid-2003", 0), row("scid-2003", None, device="d2")]))
    assert out["transformedResponse"]["isTamperProtectionEnabled"] is False
    assert out["transformedResponse"]["unreadableDevices"] == 1
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    out = tamper({"value": [{"computerDnsName": "host-a", "isTamperProtected": True},
                            {"computerDnsName": "host-b", "isTamperProtected": None}]})
    assert out["transformedResponse"]["isTamperProtectionEnabled"] is True
