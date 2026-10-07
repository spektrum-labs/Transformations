"""Every Defender secure-configuration result says what was measured: "N rated of M assessed: <verdict>".

Assessed: devices with an identified assessment row for the configuration. Rated: those Defender Vulnerability
Management reads as applicable, the only ones the verdict counts. The wording is prepended to the first reason
(and to the dataCollection error of a Not evaluated result) and the counts are added to inputSummary; the verdicts
themselves do not change. Synthetic data only.
"""
import importlib.util
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

CHECKS = {
    "iswdigestdisabled": ("isWDigestDisabled", ("scid-57",), True, False),
    "isntlmv1disabled": ("isNTLMv1Disabled", ("scid-72",), True, False),
    "issmbsigningrequired": ("isSMBSigningRequired", ("scid-95", "scid-9999"), True, False),
    "smbv1enableddevicecount": ("smbV1EnabledDeviceCount", ("scid-53", "scid-54"), 0, 1),
    "issmbclientsigningrequiredonallapplicabledevices": ("isSMBClientSigningRequiredOnAllApplicableDevices",
                                                         ("scid-95",), True, False),
}
NAMES = {
    "scid-53": "Disable SMBv1 client driver",
    "scid-54": "Disable SMBv1 server",
    "scid-57": "Disable 'WDigest Authentication'",
    "scid-72": "Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'",
    "scid-95": "Enable 'Microsoft network client: Digitally sign communications (always)'",
    "scid-9999": "Enable 'Microsoft network server: Digitally sign communications (always)'",
}
SCHEMA = [{"Name": n, "Type": "String"} for n in
          ("DeviceId", "DeviceName", "OSPlatform", "ConfigurationId", "ConfigurationName", "IsApplicable", "IsCompliant")]


def load_plain(name):
    spec = importlib.util.spec_from_file_location("roa_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed(name):
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(os.path.join(HERE, name + ".py")) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def row(device, scid, applicable=1, compliant=1):
    return {"DeviceId": "dev-" + device, "DeviceName": device + ".example.test", "OSPlatform": "Windows11",
            "ConfigurationId": scid, "ConfigurationName": NAMES[scid], "IsApplicable": applicable,
            "IsCompliant": compliant}


def result(rows):
    return {"Schema": SCHEMA, "Results": rows}


def fleet(scids, rated, assessed, bad=False):
    """`assessed` devices, the first `rated` of them applicable; with `bad`, the first one is not compliant."""
    rows = []
    for i in range(assessed):
        for scid in scids:
            applicable = 1 if i < rated else 0
            compliant = 0 if (bad and i == 0) else (1 if applicable else 0)
            rows.append(row("ws-%02d" % i, scid, applicable, compliant))
    return result(rows)


def check(out, key, value, rated, assessed, verdict):
    assert out["transformedResponse"][key] == value if value is not None else out["transformedResponse"][key] is None
    ev = out["additionalInfo"]["evaluation"]
    first = (ev["passReasons"] or ev["failReasons"])[0]
    assert first.startswith("%d rated of %d assessed: %s. " % (rated, assessed, verdict)), first
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert summary["ratedDevices"] == rated and summary["assessedDevices"] == assessed
    assert summary["ratedOfAssessed"] == "%d rated of %d assessed" % (rated, assessed)


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
@pytest.mark.parametrize("name", sorted(CHECKS))
def test_pass_fail_and_not_rated_state_the_counts(name, loader):
    key, scids, good, bad = CHECKS[name]
    transform = loader(name)
    check(transform(fleet(scids, 1, 9)), key, good, 1, 9, "compliant")
    check(transform(fleet(scids, 3, 5, bad=True)), key, bad, 3, 5, "not compliant")
    out = transform(fleet(scids, 0, 4))
    check(out, key, None, 0, 4, "not evaluated")
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
    assert out["additionalInfo"]["dataCollection"]["errors"][0].startswith("0 rated of 4 assessed: not evaluated. ")


@pytest.mark.parametrize("name", sorted(CHECKS))
@pytest.mark.parametrize("body", [None, {}, "", {"error": {"code": "Forbidden", "message": "denied"}}, result([])])
def test_nothing_read_is_zero_of_zero(name, body):
    key = CHECKS[name][0]
    check(load_plain(name)(body), key, None, 0, 0, "not evaluated")


def test_the_example_in_the_ruling():
    out = load_plain("iswdigestdisabled")(fleet(("scid-57",), 1, 9))
    assert out["additionalInfo"]["evaluation"]["passReasons"][0].startswith("1 rated of 9 assessed: compliant. ")


def test_a_device_rated_on_one_part_only_counts_once():
    rows = [row("ws-01", "scid-95"), row("ws-01", "scid-9999", 0, 0), row("ws-02", "scid-95", 0, 0),
            row("ws-02", "scid-9999", 0, 0)]
    out = load_plain("issmbsigningrequired")(result(rows))
    summary = out["additionalInfo"]["transformation"]["inputSummary"]
    assert (summary["ratedDevices"], summary["assessedDevices"]) == (1, 2)


CLIENT = "issmbclientsigningrequiredonallapplicabledevices"


def test_client_signing_is_the_kb_entry_confirmed_on_a_tenant():
    """scid-95 under its knowledge-base name: every applicable device compliant passes, one not compliant fails
    and is named; scid-95 under another name or none (the tenant's KB lacks it), or another id under that name,
    is Not evaluated, never passed."""
    transform = load_plain(CLIENT)
    good = [row("ws-01", "scid-95"), row("srv-01", "scid-95"), row("kiosk-01", "scid-95", 0, 0)]
    out = transform(result(good))
    assert out["transformedResponse"]["isSMBClientSigningRequiredOnAllApplicableDevices"] is True
    assert out["additionalInfo"]["evaluation"]["passReasons"][0].startswith("2 rated of 3 assessed: compliant. ")
    bad = [row("ws-01", "scid-95"), row("srv-01", "scid-95", 1, 0)]
    out = transform(result(bad))
    assert out["transformedResponse"]["isSMBClientSigningRequiredOnAllApplicableDevices"] is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert reason.startswith("2 rated of 2 assessed: not compliant. ") and "srv-01.example.test" in reason
    for kb_name in ("Enable 'Microsoft network server: Digitally sign communications (always)'",
                    "Disable 'WDigest Authentication'", None, ""):
        r = row("ws-01", "scid-95")
        r["ConfigurationName"] = kb_name
        assert transform(result([r]))["transformedResponse"]["isSMBClientSigningRequiredOnAllApplicableDevices"] is None
    other = row("ws-01", "scid-95")
    other["ConfigurationId"] = "scid-9999"
    assert transform(result([other]))["transformedResponse"]["isSMBClientSigningRequiredOnAllApplicableDevices"] is None


def test_client_signing_passes_where_the_superseded_check_never_can():
    """Defender's KB has no server-side signing entry: the old two-part check stays Not evaluated on the same body."""
    body = result([row("ws-01", "scid-95"), row("ws-02", "scid-95")])
    assert load_plain(CLIENT)(body)["transformedResponse"]["isSMBClientSigningRequiredOnAllApplicableDevices"] is True
    assert load_plain("issmbsigningrequired")(body)["transformedResponse"]["isSMBSigningRequired"] is None


def test_superseded_file_says_so():
    with open(os.path.join(HERE, "issmbsigningrequired.py")) as fh:
        head = fh.read(600)
    assert "SUPERSEDED" in head and "isSMBClientSigningRequiredOnAllApplicableDevices" in head and "Do not wire" in head


def test_client_signing_key_is_named_by_no_other_transform():
    key = "isSMBClientSigningRequiredOnAllApplicableDevices"
    seen = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "safeguards")):
        for fn in filenames:
            if fn.endswith(".py") and not fn.startswith("test_") and fn != CLIENT + ".py":
                with open(os.path.join(dirpath, fn), encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                if "'" + key + "'" in text or '"' + key + '"' in text:
                    seen.append(fn)
    assert seen == []
