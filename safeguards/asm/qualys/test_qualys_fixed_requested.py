"""A Qualys reply with no Fixed detection means "none fixed" only when Fixed was asked for.

Host List Detection returns New, Active and Re-Opened detections unless the request's status=
names Fixed. With echo_request=1 Qualys repeats the parameters it applied under
HOST_LIST_VM_DETECTION_OUTPUT.REQUEST.PARAM_LIST, which is the only proof the filter reached it.
So patchCompliancePercentage grades a real 0% and meanTimeToRemediateCritical reports "nothing
remediated" only when that echo names Fixed (or a Fixed row is in the reply). Otherwise the gap is
Spektrum's read: the reason says so, asks nothing of the customer, and carries errorCode
"not_measured" so diagnosis routes it to engineering.

hasHardwareAssetInventory read a key the host list never has (count) and now counts its hosts; an
empty list is a measured No. knownExploitedVulnCount, endOfLifeSoftwareDetected and
isPatchManagementEnabled read keys the reply they are given never has, and now say Not evaluated
instead of answering. Every transform is also run in the production sandbox mirror. Synthetic data.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).parent
SAFEGUARDS = HERE.parent.parent
TOOLS = SAFEGUARDS.parent / "tools"
PATCH_MGMT = SAFEGUARDS / "a6b871e6-de13-41fa-8636-81a3b6f315f4" / "is_patch_management_enabled.py"


def path_of(name):
    return PATCH_MGMT if name == "is_patch_management_enabled" else HERE / (name + ".py")


def load(name):
    spec = importlib.util.spec_from_file_location("qualys_fixed_" + name, path_of(name))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def echo(status):
    params = [{"KEY": "action", "VALUE": "list"}, {"KEY": "echo_request", "VALUE": "1"}]
    if status is not None:
        params.append({"KEY": "status", "VALUE": status})
    return {"DATETIME": "2026-11-19T00:00:00Z", "USER_LOGIN": "example_user",
            "RESOURCE": "https://qualysapi.example.invalid/api/2.0/fo/asset/host/vm/detection/",
            "PARAM_LIST": {"PARAM": params}}


def detections(*rows, request=None):
    output = {"RESPONSE": {"HOST_LIST": {"HOST": [{"ID": "1", "DETECTION_LIST": {"DETECTION": list(rows)}}]}}}
    if request is not None:
        output["REQUEST"] = request
    return {"HOST_LIST_VM_DETECTION_OUTPUT": output}


def host_list(n, warning=None):
    response = {"HOST_LIST": {"HOST": [{"ID": str(i), "IP": "192.0.2.%d" % i} for i in range(n)]}}
    if warning:
        response["WARNING"] = warning
    return {"HOST_LIST_OUTPUT": {"RESPONSE": response}}


ALL_STATUSES = "New,Active,Re-Opened,Fixed"
OPEN_CRITICAL = {"STATUS": "Active", "SEVERITY": "5"}
FIXED_LOW = {"STATUS": "Fixed", "SEVERITY": "2", "FIRST_FOUND_DATETIME": "2026-01-01T00:00:00Z",
             "LAST_FIXED_DATETIME": "2026-01-03T00:00:00Z"}
TRUNCATED = {"CODE": "1980", "TEXT": "1000 record limit exceeded.", "URL": "https://example.invalid/?id_min=1"}


def run(name, payload):
    out = load(name).transform(copy.deepcopy(payload))
    key = next(iter(out["transformedResponse"]))
    return out["transformedResponse"][key], out["additionalInfo"]


def assert_ours(info, code="not_measured"):
    collection = info["dataCollection"]
    assert collection["status"] == "error" and collection["errors"]
    assert collection["errorCode"] == code
    text = json.dumps(info["evaluation"]).lower()
    assert "request" not in text and "confirm" not in text


# --- patchCompliancePercentage --------------------------------------------------------------------

@pytest.mark.parametrize("status", [ALL_STATUSES, "new, active ,re-opened,FIXED", "NEW,ACTIVE,REOPENED,FIXED"])
def test_open_only_is_a_real_zero_once_fixed_was_requested(status):
    value, info = run("patchcompliancepercentage", detections(OPEN_CRITICAL, OPEN_CRITICAL, request=echo(status)))
    assert value == "0" and info["dataCollection"]["status"] == "success"


def test_the_full_status_set_grades_a_real_percentage():
    value, info = run("patchcompliancepercentage", detections(OPEN_CRITICAL, FIXED_LOW, request=echo(ALL_STATUSES)))
    assert value == "50" and info["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("status", ["Fixed", "Active,Fixed", "New,Re-Opened,Fixed"])
def test_a_filter_missing_an_open_status_is_not_graded(status):
    value, info = run("patchcompliancepercentage", detections(FIXED_LOW, FIXED_LOW, request=echo(status)))
    assert value is None
    assert_ours(info)


def test_fixed_rows_without_an_echo_are_not_graded():
    value, info = run("patchcompliancepercentage", detections(OPEN_CRITICAL, FIXED_LOW))
    assert value is None
    assert_ours(info)


def test_no_detections_and_no_echo_is_not_graded():
    payload = {"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": {"HOST_LIST": {"HOST": [{"ID": "1"}]}}}}
    value, info = run("patchcompliancepercentage", payload)
    assert value is None
    assert_ours(info)


def test_no_detections_with_the_full_echo_is_the_measured_hundred():
    payload = {"HOST_LIST_VM_DETECTION_OUTPUT": {"REQUEST": echo(ALL_STATUSES),
                                                 "RESPONSE": {"HOST_LIST": {"HOST": [{"ID": "1"}]}}}}
    assert run("patchcompliancepercentage", payload)[0] == "100"


@pytest.mark.parametrize("name", ["patchcompliancepercentage", "meantimetoremediatecritical",
                                  "is_patch_management_enabled"])
def test_a_truncated_detection_reply_is_a_partial_read(name):
    payload = detections(OPEN_CRITICAL, request=echo(ALL_STATUSES))
    payload["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"] = [TRUNCATED]
    value, info = run(name, payload)
    assert value is None
    assert_ours(info, "partial_read")


@pytest.mark.parametrize("request_echo", [None, echo(None), echo("New,Active,Re-Opened"), echo("Fixedish"),
                                          {"PARAM_LIST": "junk"}, {"PARAM_LIST": {"PARAM": "junk"}}])
def test_open_only_without_fixed_requested_is_ours_to_fix(request_echo):
    value, info = run("patchcompliancepercentage", detections(OPEN_CRITICAL, request=request_echo))
    assert value is None
    assert_ours(info)
    assert "Spektrum's Qualys read" in info["dataCollection"]["errors"][0]


def test_a_single_echoed_param_is_read():
    request = echo(None)
    request["PARAM_LIST"]["PARAM"] = {"KEY": "status", "VALUE": ALL_STATUSES}
    assert run("patchcompliancepercentage", detections(OPEN_CRITICAL, request=request))[0] == "0"


def test_no_hosts_is_not_measured_with_a_code():
    value, info = run("patchcompliancepercentage", {"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": {}}})
    assert value is None and info["dataCollection"]["errorCode"] == "no_data"


# --- meanTimeToRemediateCritical ------------------------------------------------------------------

def test_no_remediated_critical_with_fixed_requested_is_nothing_to_average():
    value, info = run("meantimetoremediatecritical", detections(OPEN_CRITICAL, request=echo(ALL_STATUSES)))
    assert value is None
    assert info["dataCollection"]["errorCode"] == "no_data"
    assert info["evaluation"]["recommendations"] == []


def test_a_fixed_row_of_any_severity_proves_fixed_was_requested():
    value, info = run("meantimetoremediatecritical", detections(OPEN_CRITICAL, FIXED_LOW))
    assert value is None and info["dataCollection"]["errorCode"] == "no_data"


def test_a_remediated_critical_with_no_dates_is_not_averaged_away():
    undated = {"STATUS": "Fixed", "SEVERITY": "5"}
    dated = dict(FIXED_LOW, SEVERITY="5")
    value, info = run("meantimetoremediatecritical", detections(undated, dated, request=echo(ALL_STATUSES)))
    assert value is None
    assert_ours(info)


@pytest.mark.parametrize("rows", [("x", "y"), (FIXED_LOW, "junk", "junk"), (FIXED_LOW, 3)])
def test_junk_detection_rows_are_not_graded(rows):
    value, info = run("patchcompliancepercentage", detections(*rows, request=echo(ALL_STATUSES)))
    assert value is None
    assert_ours(info)


@pytest.mark.parametrize("detection", ["garbage", 7])
def test_a_detection_list_that_is_not_a_list_is_not_graded(detection):
    payload = detections(request=echo(ALL_STATUSES))
    payload["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"][0]["DETECTION_LIST"]["DETECTION"] = detection
    assert run("patchcompliancepercentage", payload)[0] is None


def test_an_empty_detection_element_is_no_detections():
    payload = detections(request=echo(ALL_STATUSES))
    payload["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"][0]["DETECTION_LIST"]["DETECTION"] = ""
    assert run("patchcompliancepercentage", payload)[0] == "100"


def test_no_remediated_critical_without_fixed_requested_is_ours_to_fix():
    value, info = run("meantimetoremediatecritical", detections(OPEN_CRITICAL))
    assert value is None
    assert_ours(info)


# --- every not-measured path carries a code and never asks the customer to fix our read -----------

@pytest.mark.parametrize("name,payload,code", [
    ("patchcompliancepercentage", "not json", "not_measured"),
    ("patchcompliancepercentage", {"HOST_LIST_VM_DETECTION_OUTPUT": "garbage"}, "not_measured"),
    ("patchcompliancepercentage", {"SIMPLE_RETURN": {"RESPONSE": {"CODE": "1901", "TEXT": "x"}}}, "not_measured"),
    ("criticalvulnerabilitycount", {"SIMPLE_RETURN": {"RESPONSE": {"CODE": "1901", "TEXT": "x"}}}, "not_measured"),
    ("meantimetoremediatecritical", {"SIMPLE_RETURN": {"RESPONSE": {"CODE": "1901", "TEXT": "x"}}}, "not_measured"),
    ("meantimetoremediatecritical", {"HOST_LIST_VM_DETECTION_OUTPUT": "garbage"}, "not_measured"),
    ("criticalvulnerabilitycount", {"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": {}}}, "no_data"),
    ("criticalvulnerabilitycount", "not json", "not_measured"),
    ("externalassetinventorycount", {}, "not_measured"),
    ("externalassetinventorycount", host_list(0), "no_data"),
    ("externalassetinventorycount", host_list(3, TRUNCATED), "partial_read"),
])
def test_each_not_measured_path_is_coded(name, payload, code):
    value, info = run(name, payload)
    assert value is None and info["dataCollection"]["errorCode"] == code
    text = json.dumps(info["evaluation"]).lower()
    assert "request" not in text


# --- criticalVulnerabilityCount ------------------------------------------------------------------

def test_every_spelling_of_an_open_status_is_counted():
    rows = [dict(OPEN_CRITICAL, STATUS=status) for status in ("Active", "NEW", "Re-Opened", "REOPENED")]
    assert run("criticalvulnerabilitycount", detections(*rows))[0] == 4


@pytest.mark.parametrize("status", ["Fixed", "Active,Fixed"])
def test_a_filter_missing_an_open_status_is_not_a_critical_count(status):
    value, info = run("criticalvulnerabilitycount", detections(OPEN_CRITICAL, request=echo(status)))
    assert value is None
    assert_ours(info)


# --- the shared detection block -------------------------------------------------------------------

def test_the_detection_block_is_identical_in_every_reader():
    names = ["patchcompliancepercentage", "meantimetoremediatecritical", "criticalvulnerabilitycount",
             "is_patch_management_enabled"]
    blocks = set()
    for name in names:
        text = path_of(name).read_text()
        start = text.index("# --- Qualys detection reply")
        blocks.add(text[start:text.index("# --- end Qualys detection reply", start)])
    assert len(blocks) == 1


# --- hasHardwareAssetInventory --------------------------------------------------------------------

@pytest.mark.parametrize("payload", [host_list(1), host_list(1000, TRUNCATED), host_list(2, [TRUNCATED])])
def test_listed_hosts_are_a_hardware_inventory(payload):
    value, info = run("hashardwareassetinventory", payload)
    assert value is True and info["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("response", [{}, {"HOST_LIST": {"HOST": []}}, {"HOST_LIST": {}}])
def test_an_empty_host_list_is_a_measured_no(response):
    value, info = run("hashardwareassetinventory", {"HOST_LIST_OUTPUT": {"RESPONSE": response}})
    assert value is False and info["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("payload,code", [
    ({"HOST_LIST_OUTPUT": {"RESPONSE": {"HOST_LIST": {"HOST": ["junk"]}}}}, "not_measured"),
    ({"HOST_LIST_OUTPUT": {"RESPONSE": {"HOST_LIST": "junk"}}}, "not_measured"),
    ({"HOST_LIST_OUTPUT": {"RESPONSE": {"HOST_LIST": {"HOST": "junk"}}}}, "not_measured"),
    ({"count": 5}, "not_measured"),
    ({}, "not_measured"),
    ("not json", "not_measured"),
])
def test_no_listed_host_is_not_a_hardware_inventory_answer(payload, code):
    value, info = run("hashardwareassetinventory", payload)
    assert value is None and info["dataCollection"]["errorCode"] == code


# --- keys the reply never has ---------------------------------------------------------------------

def test_known_exploited_count_is_not_a_zero_from_a_detection_list():
    value, info = run("knownexploitedvulncount", detections(OPEN_CRITICAL, request=echo(ALL_STATUSES)))
    assert value is None
    assert_ours(info)


@pytest.mark.parametrize("matches,count", [([], 0), ([{"cve": "CVE-2021-44228"}, {"cve": "CVE-2014-0160"}], 2)])
def test_known_exploited_count_is_counted_when_present(matches, count):
    value, info = run("knownexploitedvulncount", {"kev_matches": matches})
    assert value == count and info["dataCollection"]["status"] == "success"


def test_end_of_life_is_not_a_no_from_a_host_list():
    value, info = run("endoflifesoftwaredetected", host_list(3))
    assert value is None
    assert_ours(info)


@pytest.mark.parametrize("lifecycle,expected", [("EOL", True), ("GA", False), ({"stage": "EOL/EOS"}, True),
                                                ({"stage": "GA"}, False), ({"stage": "EOS"}, True),
                                                ("Obsolete", True), ("End of Life", True)])
def test_end_of_life_is_read_from_an_asset_inventory(lifecycle, expected):
    payload = {"assetListData": {"asset": [{"softwareListData": {"software": [{"lifecycle": lifecycle}]}}]}}
    assert run("endoflifesoftwaredetected", payload)[0] is expected


@pytest.mark.parametrize("assets", [[{"id": 1}, {"id": 2}], [{"softwareListData": {"software": []}}],
                                    [{"softwareListData": {"software": [{"lifecycle": "Unknown"}]}}],
                                    [{"softwareListData": {"software": [{"name": "x"}]}}]])
def test_assets_without_a_readable_software_lifecycle_are_not_a_no(assets):
    value, info = run("endoflifesoftwaredetected", {"assetListData": {"asset": assets}})
    assert value is None
    assert_ours(info)


def test_an_unrecognised_lifecycle_stage_is_not_a_no():
    payload = {"assetListData": {"asset": [{"softwareListData": {"software": [{"lifecycle": "GA"},
                                                                             {"lifecycle": "Mystery"}]}}]}}
    value, info = run("endoflifesoftwaredetected", payload)
    assert value is None
    assert_ours(info)


def test_the_reason_counts_only_assets_whose_software_was_read():
    payload = {"assetListData": {"asset": [{"id": 1}, {"softwareListData": {"software": [{"lifecycle": "GA"}]}}]}}
    out = load("endoflifesoftwaredetected").transform(payload)
    assert out["transformedResponse"]["assetsScanned"] == 1
    assert "on the 1 assets" in json.dumps(out["additionalInfo"]["evaluation"])


def test_patch_management_is_not_a_no_from_a_host_list():
    value, info = run("is_patch_management_enabled", host_list(3))
    assert value is None
    assert_ours(info)


def test_patch_management_still_reads_a_detection_list():
    assert run("is_patch_management_enabled", detections(FIXED_LOW))[0] is True


def test_open_rows_only_are_not_patch_management():
    value, info = run("is_patch_management_enabled", detections(OPEN_CRITICAL))
    assert value is None
    assert_ours(info)


def test_no_fixed_row_when_fixed_was_requested_is_a_measured_no():
    value, info = run("is_patch_management_enabled", detections(OPEN_CRITICAL, request=echo("Fixed")))
    assert value is False and info["dataCollection"]["status"] == "success"


def test_no_assessed_host_is_not_a_patch_management_no():
    payload = {"HOST_LIST_VM_DETECTION_OUTPUT": {"REQUEST": echo("Fixed"), "RESPONSE": {}}}
    value, info = run("is_patch_management_enabled", payload)
    assert value is None and info["dataCollection"]["errorCode"] == "no_data"


@pytest.mark.parametrize("payload", [{}, {"SIMPLE_RETURN": {"RESPONSE": {"CODE": "1901", "TEXT": "x"}}},
                                     {"HOST_LIST_VM_DETECTION_OUTPUT": "garbage"}])
def test_a_body_that_is_not_a_detection_reply_is_not_a_no(payload):
    value, info = run("is_patch_management_enabled", payload)
    assert value is None
    assert_ours(info)


# --- review round 5 -------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["patchcompliancepercentage", "meantimetoremediatecritical"])
def test_a_truncated_reply_with_a_fixed_row_is_still_a_partial_read(name):
    payload = detections(OPEN_CRITICAL, dict(FIXED_LOW, SEVERITY="5"), request=echo(ALL_STATUSES))
    payload["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"] = TRUNCATED
    value, info = run(name, payload)
    assert value is None and info["dataCollection"]["errorCode"] == "partial_read"


def test_one_fixed_row_on_a_truncated_page_proves_patch_management():
    payload = detections(FIXED_LOW)
    payload["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"] = TRUNCATED
    assert run("is_patch_management_enabled", payload)[0] is True


@pytest.mark.parametrize("name", ["patchcompliancepercentage", "meantimetoremediatecritical",
                                  "criticalvulnerabilitycount", "is_patch_management_enabled"])
@pytest.mark.parametrize("rows", [("junk",), (FIXED_LOW, "junk"), (FIXED_LOW, 3)])
def test_every_reader_refuses_a_junk_detection_row(name, rows):
    value, info = run(name, detections(*rows, request=echo(ALL_STATUSES)))
    assert value is None
    assert_ours(info)


def test_a_fix_dated_before_its_finding_is_not_averaged_away():
    reversed_row = dict(FIXED_LOW, SEVERITY="5", LAST_FIXED_DATETIME="2025-12-01T00:00:00Z")
    dated = dict(FIXED_LOW, SEVERITY="5")
    value, info = run("meantimetoremediatecritical", detections(reversed_row, dated, request=echo(ALL_STATUSES)))
    assert value is None
    assert_ours(info)


def test_an_integration_error_is_not_a_patch_management_no():
    value, info = run("is_patch_management_enabled", {"error": True, "message": "Integration execution error: HTTP 500"})
    assert value is None
    assert_ours(info)


@pytest.mark.parametrize("host_list_value", ["junk", {"HOST": "junk"}, {"HOST": ["junk"]}, {"HOST": []}])
def test_an_unreadable_host_list_is_ours_not_nothing_scanned(host_list_value):
    payload = {"HOST_LIST_VM_DETECTION_OUTPUT": {"REQUEST": echo("Fixed"), "RESPONSE": {"HOST_LIST": host_list_value}}}
    value, info = run("is_patch_management_enabled", payload)
    assert value is None
    assert_ours(info)


@pytest.mark.parametrize("software", [[{"lifecycle": "Not EOL"}], [{"lifecycle": "GA"}, {"lifecycle": "Unknown"}],
                                      [{"lifecycle": "GA"}, {"name": "no lifecycle"}],
                                      [{"lifecycle": {"stage": "Geolocated"}}], [{"lifecycle": "GA, Unknown"}],
                                      [{"lifecycle": "GA/Unknown"}]])
def test_an_unread_lifecycle_is_not_a_no(software):
    value, info = run("endoflifesoftwaredetected", {"assetListData": {"asset": [{"softwareListData": {"software": software}}]}})
    assert value is None
    assert_ours(info)


@pytest.mark.parametrize("name", ["patchcompliancepercentage", "criticalvulnerabilitycount",
                                  "meantimetoremediatecritical", "is_patch_management_enabled"])
@pytest.mark.parametrize("host_list_value", [{"HOST": ["junk"]}, {"HOST": "junk"}, {"HOST": []}, "",
                                             {"HOST": [{"ID": "1", "DETECTION_LIST": {"DETECTION": [FIXED_LOW]}}, "junk"]}])
def test_an_unreadable_host_list_is_ours_in_every_reader(name, host_list_value):
    payload = {"HOST_LIST_VM_DETECTION_OUTPUT": {"REQUEST": echo(ALL_STATUSES), "RESPONSE": {"HOST_LIST": host_list_value}}}
    value, info = run(name, payload)
    assert value is None
    assert_ours(info)


def test_an_end_of_life_part_of_a_stage_is_end_of_life():
    payload = {"assetListData": {"asset": [{"softwareListData": {"software": [{"lifecycle": "GA"},
                                                                             {"lifecycle": {"stage": "EOL/EOS"}}]}}]}}
    assert run("endoflifesoftwaredetected", payload)[0] is True


# --- the production sandbox -----------------------------------------------------------------------

def sandboxed(name):
    sys.path.insert(0, str(TOOLS))
    try:
        import restricted_sandbox
    finally:
        sys.path.remove(str(TOOLS))
    return restricted_sandbox.load(path_of(name).read_text())["transform"]


def comparable(result):
    result = copy.deepcopy(result)
    result["additionalInfo"]["metadata"].pop("evaluatedAt", None)
    return json.dumps(result, sort_keys=True, default=str)


@pytest.mark.parametrize("name,payload", [
    ("patchcompliancepercentage", detections(OPEN_CRITICAL, request=echo(ALL_STATUSES))),
    ("patchcompliancepercentage", detections(OPEN_CRITICAL)),
    ("meantimetoremediatecritical", detections(OPEN_CRITICAL, request=echo(ALL_STATUSES))),
    ("criticalvulnerabilitycount", detections(OPEN_CRITICAL)),
    ("externalassetinventorycount", host_list(2)),
    ("hashardwareassetinventory", host_list(2)),
    ("knownexploitedvulncount", detections(OPEN_CRITICAL)),
    ("endoflifesoftwaredetected", host_list(2)),
    ("is_patch_management_enabled", host_list(2)),
    ("is_patch_management_enabled", detections(FIXED_LOW, request=echo(ALL_STATUSES))),
    ("is_patch_management_enabled", detections(FIXED_LOW, "junk")),
    ("patchcompliancepercentage", detections(FIXED_LOW, "junk", request=echo(ALL_STATUSES))),
    ("meantimetoremediatecritical", detections(dict(FIXED_LOW, SEVERITY="5"), request=echo(ALL_STATUSES))),
    ("criticalvulnerabilitycount", {"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": {"HOST_LIST": {"HOST": ["junk"]}}}}),
    ("endoflifesoftwaredetected", {"assetListData": {"asset": [{"softwareListData": {"software": [
        {"lifecycle": "GA"}, {"lifecycle": {"stage": "EOL/EOS"}}]}}]}}),
    ("endoflifesoftwaredetected", {"assetListData": {"asset": [{"softwareListData": {"software": [
        {"lifecycle": "GA"}, {"lifecycle": "GA/Unknown"}]}}]}}),
])
def test_each_transform_answers_the_same_in_the_sandbox(name, payload):
    boxed = sandboxed(name)(copy.deepcopy(payload))
    assert comparable(boxed) == comparable(load(name).transform(copy.deepcopy(payload)))


# --- review round 7 -------------------------------------------------------------------------------

EIGHT = ["patchcompliancepercentage", "meantimetoremediatecritical", "criticalvulnerabilitycount",
         "is_patch_management_enabled", "endoflifesoftwaredetected", "externalassetinventorycount",
         "hashardwareassetinventory", "knownexploitedvulncount"]
REFUSALS = [{"error": True, "message": "Integration execution error: HTTP 401"},
            {"message": "Integration execution error: HTTP 403"}, {"statusCode": 401, "error": "Unauthorized"},
            {"SIMPLE_RETURN": {"RESPONSE": {"CODE": "2000", "TEXT": "Bad Login/Password"}}}]


@pytest.mark.parametrize("name", EIGHT)
@pytest.mark.parametrize("payload", REFUSALS)
def test_a_refused_credential_is_the_customers_to_fix(name, payload):
    value, info = run(name, payload)
    assert value is None and info["dataCollection"]["errorCode"] == "vendor_refusal"
    assert info["evaluation"]["recommendations"] == [load(name).VERIFY_ACCESS]
    assert "Spektrum's side" not in json.dumps(info)


@pytest.mark.parametrize("name", EIGHT)
def test_a_rejected_parameter_stays_ours(name):
    value, info = run(name, {"SIMPLE_RETURN": {"RESPONSE": {"CODE": "1901", "TEXT": "Unrecognized parameter"}}})
    assert value is None and info["dataCollection"]["errorCode"] != "vendor_refusal"


def test_the_refusal_block_is_identical_in_every_reader():
    blocks = set()
    for name in EIGHT:
        text = path_of(name).read_text()
        start = text.index("# --- Qualys refusal")
        blocks.add(text[start:text.index("# --- end Qualys refusal", start)])
    assert len(blocks) == 1


def test_a_truncated_reply_with_open_criticals_fails_on_a_lower_bound():
    payload = detections(OPEN_CRITICAL, OPEN_CRITICAL, request=echo(ALL_STATUSES))
    payload["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"] = TRUNCATED
    out = load("criticalvulnerabilitycount").transform(payload)
    assert out["transformedResponse"]["criticalVulnerabilityCount"] == 2
    assert out["transformedResponse"]["countIsLowerBound"] is True
    assert "criticalVulnerabilityCount: at least 2" in out["additionalInfo"]["evaluation"]["additionalFindings"]


def test_a_truncated_reply_with_no_open_critical_is_a_partial_read():
    payload = detections(dict(FIXED_LOW, SEVERITY="5"), request=echo(ALL_STATUSES))
    payload["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"] = TRUNCATED
    value, info = run("criticalvulnerabilitycount", payload)
    assert value is None
    assert_ours(info, "partial_read")


@pytest.mark.parametrize("row", [{"SEVERITY": "5"}, {"SEVERITY": "4", "STATUS": ""}, {"SEVERITY": "5", "STATUS": "Ignored"}])
def test_a_critical_with_no_known_status_counts_as_open(row):
    assert run("criticalvulnerabilitycount", detections(row))[0] == 1
