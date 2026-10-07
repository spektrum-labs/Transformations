"""Defender Vulnerability Management secure-configuration checks (EP-005 / EP-007):
smbV1EnabledDeviceCount, isWDigestDisabled, isNTLMv1Disabled, isSMBSigningRequired,
isScreenLockWithin15MinutesEnforced, isLAPSEnabledOnAllDevices.

Fixtures follow the advanced-hunting response shape ({"Schema": [...], "Results": [...]}) of the query each
new One-Click method runs (DeviceTvmSecureConfigurationAssessment joined with its KB table). Every check is
run with typed values and with the stringified values Token-Service stores ("1", "True", "None"), plain and
through the Token-Service RestrictedPython replica. Device names and ids are synthetic.
"""
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))

NAMES = {
    "scid-53": "Disable SMBv1 client driver",
    "scid-54": "Disable SMBv1 server",
    "scid-28": "Set 'Interactive logon: Machine inactivity limit' to '1-900 seconds'",
    "scid-113": "Ensure LAPS is enabled on every endpoint and server",
    "scid-57": "Disable 'WDigest Authentication'",
    "scid-72": "Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'",
    "scid-95": "Enable 'Microsoft network client: Digitally sign communications (always)'",
    "scid-9999": "Enable 'Microsoft network server: Digitally sign communications (always)'",
}

CHECKS = {
    "smbv1enableddevicecount": ("smbV1EnabledDeviceCount", ("scid-53", "scid-54")),
    "iswdigestdisabled": ("isWDigestDisabled", ("scid-57",)),
    "isntlmv1disabled": ("isNTLMv1Disabled", ("scid-72",)),
    "issmbsigningrequired": ("isSMBSigningRequired", ("scid-95", "scid-9999")),
    "isscreenlockwithin15minutesenforced": ("isScreenLockWithin15MinutesEnforced", ("scid-28",)),
    "islapsenabledonalldevices": ("isLAPSEnabledOnAllDevices", ("scid-113",)),
}

SAFE = {"smbV1EnabledDeviceCount": 0, "isWDigestDisabled": True, "isNTLMv1Disabled": True,
        "isSMBSigningRequired": True, "isScreenLockWithin15MinutesEnforced": True,
        "isLAPSEnabledOnAllDevices": True}


def load_plain(name):
    spec = importlib.util.spec_from_file_location("tvm_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed(name):
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(os.path.join(HERE, name + ".py")) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


def row(device, scid, applicable=1, compliant=1, name=None):
    return {"DeviceId": "dev-" + device, "DeviceName": device + ".example.test", "OSPlatform": "Windows11",
            "ConfigurationId": scid, "ConfigurationName": NAMES.get(scid) if name is None else name,
            "IsApplicable": applicable, "IsCompliant": compliant}


SCHEMA = [{"Name": n, "Type": "String"} for n in
          ("DeviceId", "DeviceName", "OSPlatform", "ConfigurationId", "ConfigurationName", "IsApplicable", "IsCompliant")]


def result(rows):
    return {"Schema": SCHEMA, "Results": rows, "Stats": {"dataset_statistics": [{"table_row_count": len(rows)}]}}


def stringify(value):
    """Token-Service stores every leaf str()'d: 1 -> "1", True -> "True", None -> "None"."""
    if isinstance(value, dict):
        return {k: stringify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [stringify(v) for v in value]
    return str(value)


def ts_wrap(body):
    return {"data": {"apiResponse": body}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


def fleet(scids, bad=None):
    """Three devices assessed for every scid; `bad` is (device, scid) made non-compliant; one not applicable."""
    rows = []
    for dev in ("ws-01", "ws-02", "srv-01"):
        for scid in scids:
            compliant = 0 if bad == (dev, scid) else 1
            rows.append(row(dev, scid, 1, compliant))
    rows.append(row("kiosk-01", scids[0], 0, 0))
    return result(rows)


def value(name, body, loader=load_plain):
    out = loader(name)(body)
    return out["transformedResponse"][CHECKS[name][0]], out


NO_EVIDENCE = [
    {}, None, "", "{}", "not json",
    {"error": {"type": "authentication_error", "message": "invalid credentials"}},
    {"statusCode": 401, "error": "Unauthorized"},
    {"status_code": 401, "error": "Unauthorized"},
    {"error": {"statusCode": 401, "message": "Unauthorized"}},
    {"statusCode": 403, "error": "Forbidden"},
    {"error": {"code": "Forbidden", "message": "Missing application roles. API required roles: AdvancedQuery.Read.All"}},
    {"error": True, "message": "HTTP 400: query failed"},
    {"hello": "world"},
    {"foo": {"bar": [1, 2, 3]}},
    {"Results": []},
    {"Schema": SCHEMA},
    result([]),
]


@pytest.mark.parametrize("name", sorted(CHECKS))
@pytest.mark.parametrize("body", NO_EVIDENCE)
def test_no_evidence_is_not_evaluated(name, body):
    for wrapped in (body, ts_wrap(body)):
        got, out = value(name, wrapped)
        assert got is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
        assert out["additionalInfo"]["dataCollection"]["errors"]


@pytest.mark.parametrize("loader", [load_plain, load_sandboxed])
@pytest.mark.parametrize("form", ["typed", "stringified", "wrapped", "json-string"])
@pytest.mark.parametrize("name", sorted(CHECKS))
def test_pass_and_fail(name, form, loader):
    key, scids = CHECKS[name]
    good = fleet(scids)
    bad = fleet(scids, bad=("srv-01", scids[-1]))
    if form == "stringified":
        good, bad = stringify(good), stringify(bad)
    if form == "wrapped":
        good, bad = ts_wrap(good), ts_wrap(bad)
    if form == "json-string":
        good, bad = json.dumps(good), json.dumps(bad)
    got_good, out_good = value(name, good, loader)
    got_bad, out_bad = value(name, bad, loader)
    assert got_good == SAFE[key]
    assert out_good["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out_good["additionalInfo"]["transformation"]["inputSummary"]["applicableDevices"] == 3
    if key == "smbV1EnabledDeviceCount":
        assert got_bad == 1
    else:
        assert got_bad is False
    reason = out_bad["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "srv-01.example.test" in reason
    assert "1 of 3 applicable" in reason


def test_smbv1_counts_devices_not_rows():
    rows = [row("ws-01", "scid-53", 1, 0), row("ws-01", "scid-54", 1, 0), row("ws-02", "scid-53", 1, 0),
            row("ws-02", "scid-54", 1, 1), row("ws-03", "scid-53", 1, 1), row("ws-03", "scid-54", 1, 1)]
    got, out = value("smbv1enableddevicecount", result(rows))
    assert got == 2
    assert "SMBv1 client driver, SMBv1 server" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_duplicate_rows_keep_the_worst_reading():
    rows = [row("ws-01", "scid-57", 1, 1), row("ws-01", "scid-57", 1, 0)]
    assert value("iswdigestdisabled", result(rows))[0] is False


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_partial_result_at_row_limit_is_not_evaluated(name):
    scid = CHECKS[name][1][0]
    rows = [row("ws-%05d" % i, scid) for i in range(100000)]
    got, out = value(name, result(rows))
    assert got is None
    assert "limit" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_no_applicable_device_is_not_evaluated(name):
    rows = [row("kiosk-01", s, 0, 0) for s in CHECKS[name][1]]
    assert value(name, result(rows))[0] is None


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_a_missing_part_or_unknown_row_is_not_evaluated(name):
    scids = CHECKS[name][1]
    # a configuration id whose KB name does not say what the id is expected to mean
    renamed = fleet(scids)
    renamed["Results"][0]["ConfigurationName"] = "Turn on Microsoft Defender Antivirus"
    assert value(name, renamed)[0] is None
    # a row with no KB name at all (the join found nothing)
    unnamed = fleet(scids)
    unnamed["Results"][0]["ConfigurationName"] = None
    assert value(name, unnamed)[0] is None
    # an unexpected configuration id
    extra = fleet(scids)
    extra["Results"].append(row("ws-01", "scid-2010", name="Turn on Microsoft Defender Antivirus"))
    assert value(name, extra)[0] is None
    if len(scids) > 1:
        only_first = result([row("ws-01", scids[0])])
        assert value(name, only_first)[0] is None


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_unreadable_flags_are_not_evaluated(name):
    scids = CHECKS[name][1]
    body = fleet(scids)
    body["Results"][0]["IsCompliant"] = "None"
    assert value(name, body)[0] is None
    body = fleet(scids)
    body["Results"][0]["IsApplicable"] = None
    assert value(name, body)[0] is None


def test_smb_signing_needs_the_server_side():
    """Client signing alone never passes: the server-side configuration must be assessed too."""
    rows = [row(d, "scid-95") for d in ("ws-01", "ws-02")]
    got, out = value("issmbsigningrequired", result(rows))
    assert got is None
    assert "SMB server signing" in out["additionalInfo"]["evaluation"]["failReasons"][0]


class Poisoned(dict):
    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_except_path_is_not_evaluated(name):
    got, out = value(name, Poisoned())
    assert got is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("name", sorted(CHECKS))
def test_module_declares_none_means_not_evaluated(name):
    spec = importlib.util.spec_from_file_location("decl_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.NONE_MEANS_NOT_EVALUATED == (CHECKS[name][0],)


def test_keys_are_new_and_no_existing_transform_emits_them():
    """Additive only: no transform outside these files names these keys, so wiring them cannot change any
    existing check's output."""
    keys = [CHECKS[n][0] for n in CHECKS]
    ours = set(os.path.join(HERE, n + ".py") for n in CHECKS)
    seen = []
    for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, "safeguards")):
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if not fn.endswith(".py") or fn.startswith("test_") or path in ours:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for k in keys:
                if '"' + k + '"' in text or "'" + k + "'" in text:
                    seen.append((path, k))
    assert seen == []


def test_smb_signing_device_with_client_reading_only_is_not_evaluated():
    """Device A has both sides compliant; device B has only a compliant client reading: B is not shown to comply."""
    rows = [row("ws-01", "scid-95"), row("ws-01", "scid-9999"), row("ws-02", "scid-95")]
    got, out = value("issmbsigningrequired", result(rows))
    assert got is None
    assert "ws-02.example.test" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_a_confirmed_failure_still_fails_when_another_device_is_partly_assessed():
    rows = [row("ws-01", "scid-95", 1, 0), row("ws-01", "scid-9999"), row("ws-02", "scid-95")]
    assert value("issmbsigningrequired", result(rows))[0] is False
    rows = [row("ws-01", "scid-53", 1, 0), row("ws-01", "scid-54"), row("ws-02", "scid-53")]
    assert value("smbv1enableddevicecount", result(rows))[0] == 1
    rows = [row("ws-01", "scid-53"), row("ws-01", "scid-54"), row("ws-02", "scid-53")]
    assert value("smbv1enableddevicecount", result(rows))[0] is None


def test_the_client_id_never_counts_as_the_server_side():
    rows = [row("ws-01", "scid-95", name="Enable 'Microsoft network server: Digitally sign communications (always)'")]
    assert value("issmbsigningrequired", result(rows))[0] is None


def test_a_count_with_partly_assessed_devices_says_it_is_a_lower_bound():
    rows = [row("ws-01", "scid-53", 1, 0), row("ws-01", "scid-54"), row("ws-02", "scid-53")]
    got, out = value("smbv1enableddevicecount", result(rows))
    assert got == 1
    assert "count may be higher: ws-02.example.test" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_a_part_no_device_finds_applicable_was_not_measured():
    rows = [row(d, "scid-95") for d in ("ws-01", "ws-02")] + [row(d, "scid-9999", 0, 0) for d in ("ws-01", "ws-02")]
    got, out = value("issmbsigningrequired", result(rows))
    assert got is None
    assert "SMB server signing" in out["additionalInfo"]["evaluation"]["failReasons"][0]
    rows = [row(d, "scid-53") for d in ("ws-01", "ws-02")] + [row(d, "scid-54", 0, 0) for d in ("ws-01", "ws-02")]
    assert value("smbv1enableddevicecount", result(rows))[0] is None


@pytest.mark.parametrize("bad_id", ["", "None", "scid-", "x-12", "scid-12a"])
def test_a_name_only_part_needs_a_well_formed_id(bad_id):
    rows = [row("ws-01", "scid-95"),
            row("ws-01", bad_id, name="Enable 'Microsoft network server: Digitally sign communications (always)'")]
    assert value("issmbsigningrequired", result(rows))[0] is None


def test_screen_lock_reads_only_the_pinned_id_under_its_knowledge_base_name():
    """scid-28 counts only while its KB name says "machine inactivity limit"; another id carrying that name, or
    scid-28 under another name (or none: the tenant's KB lacks it), is Not evaluated, never passed."""
    name = "isscreenlockwithin15minutesenforced"
    good = [row(d, "scid-28") for d in ("ws-01", "ws-02")]
    assert value(name, result(good))[0] is True
    other_id = [row("ws-01", "scid-9998", name=NAMES["scid-28"])]
    assert value(name, result(other_id))[0] is None
    for kb_name in ("Turn on screen saver", "Enable 'Require password on wake'", None, ""):
        bad = row("ws-01", "scid-28")
        bad["ConfigurationName"] = kb_name
        got, out = value(name, result([bad]))
        assert got is None
        assert "scid-28" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_screen_lock_names_the_device_over_the_limit():
    rows = [row("ws-01", "scid-28"), row("ws-02", "scid-28", 1, 0), row("kiosk-01", "scid-28", 0, 0)]
    got, out = value("isscreenlockwithin15minutesenforced", result(rows))
    assert got is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "1 of 2 applicable" in reason and "ws-02.example.test" in reason
    assert "1-900 seconds" in reason
    assert "Machine inactivity limit" in out["additionalInfo"]["evaluation"]["recommendations"][0]


def test_laps_reads_only_the_pinned_id_under_its_knowledge_base_name():
    """scid-113 counts only while its KB name says LAPS is enabled; another id under that name, or scid-113 under
    another name (or none: the tenant's KB lacks it), is Not evaluated, never passed."""
    name = "islapsenabledonalldevices"
    good = [row(d, "scid-113") for d in ("ws-01", "srv-01")]
    assert value(name, result(good))[0] is True
    assert value(name, result([row("ws-01", "scid-9997", name=NAMES["scid-113"])]))[0] is None
    for kb_name in ("Set 'Interactive logon: Machine inactivity limit' to '1-900 seconds'",
                    "Disable 'WDigest Authentication'", None, ""):
        bad = row("ws-01", "scid-113")
        bad["ConfigurationName"] = kb_name
        got, out = value(name, result([bad]))
        assert got is None
        assert "scid-113" in out["additionalInfo"]["evaluation"]["failReasons"][0]


def test_laps_names_the_server_without_it():
    rows = [row("ws-01", "scid-113"), row("srv-01", "scid-113", 1, 0), row("kiosk-01", "scid-113", 0, 0)]
    got, out = value("islapsenabledonalldevices", result(rows))
    assert got is False
    reason = out["additionalInfo"]["evaluation"]["failReasons"][0]
    assert "1 of 2 applicable" in reason and "srv-01.example.test" in reason and "LAPS enabled" in reason


def test_a_tenant_without_vulnerability_management_tables_is_not_evaluated():
    """No TVM tables (licence): the fuzzy unions return an empty result, which never passes or fails."""
    for name in ("isscreenlockwithin15minutesenforced", "islapsenabledonalldevices"):
        got, out = value(name, ts_wrap(result([])))
        assert got is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
