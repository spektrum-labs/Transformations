"""CrashPlan (7403F9D5): isBackupTypesScheduled from the two-step workflow (list active computers, then
GET /api/v1/Computer/{computerId}?incSettings=true per computer). SYNTHETIC fixtures only, shaped from the
documented schema (code42/py42 DeviceSettings test fixture, code42/code42-mock-servers docs/core.yml); no
tenant body. True only when every active, unblocked CrashPlan computer has a non-legal-hold backup set with a
destination, a run window that lets it run and a positive backup frequency. An explicitly unscheduled
computer is False. Every no-data or partial read is not evaluated (None, dataCollection error), never True.
Each case runs as plain Python and in the Token-Service sandbox replica (tools/restricted_sandbox.py).
"""
import copy
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NAME = "isbackuptypesscheduled"
KEY = "isBackupTypesScheduled"

TAG = "crashplanibts"
try:
    import RestrictedPython  # noqa: F401
    spec = importlib.util.spec_from_file_location("restricted_sandbox_" + TAG, ROOT / "tools" / "restricted_sandbox.py")
    sandbox = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sandbox)
    load_code = sandbox.load
except ImportError:
    # without RestrictedPython the "sandbox" leg runs as plain exec (CI installs requirements-test.txt,
    # which carries RestrictedPython, so CI runs the real sandbox)
    def load_code(code, filename):
        ns = {"__name__": TAG + "_sandbox"}
        exec(compile(code, filename, "exec"), ns)
        return ns

MODES = ["python", "sandbox"]


def load(mode):
    path = HERE / (NAME + ".py")
    if mode == "sandbox":
        return load_code(path.read_text(), "<transformation>")["transform"]
    spec = importlib.util.spec_from_file_location(TAG + "_" + NAME, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.transform


def run(body, mode):
    out = load(mode)(copy.deepcopy(body))
    return out["transformedResponse"].get(KEY), out["additionalInfo"]["dataCollection"]["status"], out


def ts(body):
    return {"data": body, "validation": {"status": "skipped", "errors": [], "warnings": []}}


WRAPS = [lambda b: b, ts]

# ---- synthetic fixtures -------------------------------------------------------------------------------------

ALWAYS = [{"@always": "true", "@days": "SMTWHFS", "@startTimeOfDay": "01:00", "@endTimeOfDay": "06:00"}]
WINDOW = [{"@always": "false", "@days": "MTWHF", "@startTimeOfDay": "19:00", "@endTimeOfDay": "07:00"}]
NEVER = [{"@always": "false", "@days": "", "@startTimeOfDay": "01:00", "@endTimeOfDay": "06:00"}]


def computer(cid, blocked=False, active=True, service="CrashPlan"):
    return {"computerId": cid, "guid": "9000000" + str(cid), "name": "device-" + str(cid), "active": active,
            "blocked": blocked, "service": service, "status": "Active", "orgId": 424242}


def backup_set(sid="1", window=None, destinations=None, frequency="900000"):
    return {"@id": sid, "name": "BackupSet " + sid,
            "backupRunWindow": copy.deepcopy(ALWAYS if window is None else window),
            "destinations": [{"@id": "4200"}] if destinations is None else destinations,
            "retentionPolicy": {"backupFrequency": frequency, "keepDeleted": "true"},
            "scanInterval": "86400000", "watchFiles": "true"}


def legal_hold_set(sid="99"):
    s = backup_set(sid)
    s["destinations"] = {"@locked": "true", "destination": [{"@id": "4300"}]}
    return s


def settings_body(cid, sets):
    return {"metadata": {"params": {"incSettings": "true"}},
            "data": {"computerId": cid, "guid": "9000000" + str(cid), "active": True,
                     "settings": {"serviceBackupConfig": {"backupConfig": {"backupSets": sets}}}}}


def documented():
    # 1001: always-on set. 1002: evenings set plus a legal-hold set. 1003: blocked, out of scope, no settings.
    return {
        "computerList": {"metadata": {"params": {"active": "true", "pgNum": "1", "pgSize": "100"}},
                         "data": {"totalCount": 3, "warningCount": 0,
                                  "computers": [computer(1001), computer(1002), computer(1003, blocked=True)]}},
        "computerSettings": [settings_body(1001, [backup_set("1")]),
                             settings_body(1002, [backup_set("1", window=WINDOW, frequency="3600000"),
                                                  legal_hold_set()])],
    }


def sets_of(body, i):
    return body["computerSettings"][i]["data"]["settings"]["serviceBackupConfig"]["backupConfig"]["backupSets"]


def with_change(change):
    b = documented()
    change(b)
    return b


# ---- pass ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", WRAPS)
def test_documented_shape_passes(mode, wrap):
    v, dc, out = run(wrap(documented()), mode)
    assert (v, dc) == (True, "success")
    tr = out["transformedResponse"]
    assert tr["computersEvaluated"] == 2
    assert tr["computersScheduled"] == 2
    assert tr["computersOutOfScope"] == 1  # the blocked device
    assert tr["runWindowTypes"] == ["always", "window"]
    assert (tr["shortestBackupFrequencyMinutes"], tr["longestBackupFrequencyMinutes"]) == (15, 60)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("raw", [lambda b: {"apiResponse": b}, lambda b: {"response": {"result": b}}, json.dumps])
def test_wrapped_and_string_inputs_pass(mode, raw):
    assert run(raw(documented()), mode)[:2] == (True, "success")


@pytest.mark.parametrize("mode", MODES)
def test_locked_values_and_locked_set_count_pass(mode):
    def change(b):
        s = sets_of(b, 0)[0]
        s["retentionPolicy"]["backupFrequency"] = {"#text": "900000", "@locked": "true"}
        b["computerSettings"][0]["data"]["settings"]["serviceBackupConfig"]["backupConfig"]["backupSets"] = \
            {"@locked": "true", "backupSet": s}
    assert run(with_change(change), mode)[:2] == (True, "success")


# ---- explicitly unscheduled: False --------------------------------------------------------------------------

def flipped(b):
    sets_of(b, 1)[0]["destinations"] = {"@cleared": "true"}  # 1002's user set backs up nowhere


def window_never(b):
    sets_of(b, 0)[0]["backupRunWindow"] = copy.deepcopy(NEVER)


def zero_frequency(b):
    sets_of(b, 0)[0]["retentionPolicy"]["backupFrequency"] = "0"


def no_sets(b):
    b["computerSettings"][0]["data"]["settings"]["serviceBackupConfig"]["backupConfig"]["backupSets"] = []


def only_legal_hold(b):
    sets_of(b, 1).pop(0)  # 1002 keeps only its legal-hold set


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", WRAPS)
@pytest.mark.parametrize("change,bad_id", [(flipped, "1002"), (window_never, "1001"), (zero_frequency, "1001"),
                                           (no_sets, "1001"), (only_legal_hold, "1002")],
                         ids=["flipped-no-destination", "window-never", "zero-frequency", "no-sets",
                              "only-legal-hold-set"])
def test_explicitly_unscheduled_fails(mode, wrap, change, bad_id):
    v, dc, out = run(wrap(with_change(change)), mode)
    assert (v, dc) == (False, "success")
    assert out["transformedResponse"]["notScheduledComputerIds"] == [bad_id]


# ---- no data or partial data: Unevaluated, never True -------------------------------------------------------

NO_EVIDENCE = [
    None, {}, [], "", "not json", b"",
    {"error": True, "errorType": "vendor", "status": "Error", "message": "Internal Server Error", "statusCode": 500},
    {"error": {"code": 403, "message": "Forbidden"}, "status_code": 403},
    {"statusCode": 401, "message": "Unauthorized"},
    {"status_code": 429, "message": "Too Many Requests"},
    {"status": "Error", "response_metadata": {"status_code": 404}, "apiResponse": {"status": "Error"}},
    {"error": True, "statusCode": 412, "message": "Required integration credentials are not connected"},
    {"hello": "world"},
    {"computerList": {"data": {"computers": "x"}}},
    {"computerSettings": []},
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("b", NO_EVIDENCE, ids=[str(i) for i in range(len(NO_EVIDENCE))])
def test_no_evidence_is_unevaluated(mode, b):
    for x in (b, ts(b)):
        v, dc, out = run(x, mode)
        assert (v, dc) == (None, "error")
        assert out["additionalInfo"]["dataCollection"]["errors"]


def missing_settings_body(b):
    b["computerSettings"].pop(1)


def partial_list(b):
    b["computerList"]["data"]["totalCount"] = 250


def partial_list_and_flipped(b):
    partial_list(b)
    flipped(b)


def per_computer_error(b):
    b["computerSettings"][0] = {"error": True, "status": "Error", "statusCode": 500, "message": "Internal Server Error"}


def per_computer_4xx(b):
    b["computerSettings"][1] = {"status_code": 403, "message": "Forbidden"}


def per_computer_error_and_flipped(b):
    flipped(b)
    per_computer_error(b)


def settings_not_returned(b):
    b["computerSettings"][0]["data"].pop("settings")


def set_without_schedule_fields(b):
    s = sets_of(b, 0)[0]
    s.pop("backupRunWindow")
    s.pop("retentionPolicy")


def all_blocked(b):
    for c in b["computerList"]["data"]["computers"]:
        c["blocked"] = True


def incydr_only(b):
    for c in b["computerList"]["data"]["computers"]:
        c["service"] = "Incydr"


def empty_org(b):
    b["computerList"]["data"] = {"totalCount": 0, "computers": []}
    b["computerSettings"] = []


PARTIAL = [missing_settings_body, partial_list, partial_list_and_flipped, per_computer_error, per_computer_4xx,
           per_computer_error_and_flipped, settings_not_returned, set_without_schedule_fields,
           all_blocked, incydr_only, empty_org]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("wrap", WRAPS)
@pytest.mark.parametrize("change", PARTIAL, ids=[f.__name__ for f in PARTIAL])
def test_partial_or_out_of_scope_is_unevaluated(mode, wrap, change):
    v, dc, out = run(wrap(with_change(change)), mode)
    assert (v, dc) == (None, "error")
    assert out["additionalInfo"]["dataCollection"]["errors"]


# ---- backward safety: the live one-step listBackupSets workflow ---------------------------------------------
# Until the definition change lands, the workflow still calls
# GET {$baseURL}/api/v1/computers/{$computerId}/backupSets, with {$computerId} unbound, and gets a 404.
# The old transform read every one of these as False (a false red). The new one must read them as
# not evaluated: None, never False and never True.

OLD_404_BODIES = [
    {"error": True, "status": "Error", "statusCode": 404, "message": "Not Found"},
    {"status_code": 404, "content_type": "text/html", "_response_data": "<html><body>404 Not Found</body></html>",
     "url": "https://console.us2.crashplan.com/api/v1/computers/{$computerId}/backupSets"},
    {"status": "Error", "response_metadata": {"status_code": 404},
     "apiResponse": {"status": "Error", "message": "Not Found"}},
    {"apiResponse": {"error": True, "status": "Error", "statusCode": 404, "message": "Not Found"}},
    [{"name": "NOT_FOUND", "description": "Not Found", "objects": []}],
    "<html><body>404 Not Found</body></html>",
]


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("b", OLD_404_BODIES, ids=[str(i) for i in range(len(OLD_404_BODIES))])
def test_old_definition_404_is_unevaluated_not_false(mode, b):
    for x in (b, ts(b)):
        v, dc, out = run(x, mode)
        assert v is None, "old 404 input must not be judged (got %r)" % (v,)
        assert dc == "error"
