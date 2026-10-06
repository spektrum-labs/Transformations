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
