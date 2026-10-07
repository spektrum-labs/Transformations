"""Qualys detection STATUS casing, and a truncated host list (7 Oct 2026).

Two defects on the four criteria whose workflow method is `getVulnerabilities`
(Host List Detection, `/api/2.0/fo/asset/host/vm/detection/?action=list`).

**Casing.** The code matched `STATUS` exactly against `['New', 'Active', 'Re-Opened']` and
`== 'Fixed'`. Qualys ships one state in two casings and two separator conventions, in the same
section of its own reference: the endpoint description names them `NEW, ACTIVE, FIXED, REOPENED`
(VM/PC API user guide p1119) while the `status=` parameter table names them
`New, Active, Re-Opened, Fixed` (p1132), and the published output samples carry `Active` 43
times and `ACTIVE` 5 times (p1144 and p1145 respectively). On an uppercase-emitting platform the
exact test dropped every open critical, so `criticalVulnerabilityCount` read 0 and passed
`lessThan 10` with the estate on fire -- and `patchCompliancePercentage` read 0 % on a fully
patched estate, which is a fabricated gap in the other direction.

**Truncation.** The definition's `getVulnerabilities` sends no `truncation_limit`. The vendor
caps the reply at 1000 host records when it is not sent, and signals it with
`<WARNING><CODE>1980</CODE>` carrying the URL for the next batch (p1127 for the default, p1143
for the warning element, p617 for the warning at the default limit). Nothing here follows that
URL, so the counts, the mean and the percentage were computed over a sample and reported as the
estate. A body carrying that warning now answers `None` with the reason in
`dataCollection.errors`, which Token-Service grades as Unevaluated.

Bodies are the vendor's published Host List Detection V2.0 shape parsed the way
Integration-Service parses it (`xmltodict`), reduced to the fields these transformations read.
A `Fixed` detection has no published sample anywhere in the 2,049-page guide -- only New, Active
and ACTIVE do -- so the `Fixed`/`FIXED` bodies are built from the documented enum, and are
weaker evidence than the `Active`/`ACTIVE` ones by exactly that much.

What this does NOT change, deliberately: an empty body still answers a graded number
(`criticalVulnerabilityCount` 0, `patchCompliancePercentage` 100), and a body whose reads raise
still answers a graded number rather than a not-measured. Both are separate findings with
separate fixes, and the tests below pin the current behaviour so that neither is quietly
altered here.
"""
import importlib.util
import pathlib

import pytest

HERE = pathlib.Path(__file__).parent

# p1143, verbatim but for the record count, which p617 shows at the default limit of 1000.
TRUNCATION_WARNING = {
    "CODE": "1980",
    "TEXT": "1000 record limit exceeded. Use URL to get next batch of results.",
    "URL": "<qualys_base_url>/api/2.0/fo/asset/host/vm/detection/?action=list&id_min=5641289",
}


def load(name):
    spec = importlib.util.spec_from_file_location("qualys_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def detection(severity, status, last_fixed=None):
    d = {"QID": "13361", "TYPE": "Confirmed", "SEVERITY": str(severity), "STATUS": status,
         "FIRST_FOUND_DATETIME": "2026-01-10T07:11:13Z",
         "LAST_FOUND_DATETIME": "2026-09-27T23:04:10Z"}
    if last_fixed:
        d["LAST_FIXED_DATETIME"] = last_fixed
    return d


def reply(detections, truncated=False):
    response = {"DATETIME": "2026-10-07T09:03:45Z",
                "HOST_LIST": {"HOST": {"ID": "4203254", "IP": "10.10.10.9",
                                       "DETECTION_LIST": {"DETECTION": detections}}}}
    if truncated:
        response["WARNING"] = TRUNCATION_WARNING
    return {"HOST_LIST_VM_DETECTION_OUTPUT": {"RESPONSE": response}}


def value_and_status(out, key):
    return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]


# --- F-ASM-26: the casing of STATUS must not decide the answer ------------------------------

@pytest.mark.parametrize("status", ["Active", "ACTIVE", "active"])
def test_an_open_critical_is_counted_in_every_casing_the_vendor_ships(status):
    out = load("criticalvulnerabilitycount")(reply([detection(5, status)] * 12))
    assert value_and_status(out, "criticalVulnerabilityCount") == (12, "success")


@pytest.mark.parametrize("status", ["Re-Opened", "REOPENED", "re-opened"])
def test_a_reopened_critical_is_counted_in_every_spelling(status):
    out = load("criticalvulnerabilitycount")(reply([detection(4, status)]))
    assert value_and_status(out, "criticalVulnerabilityCount") == (1, "success")


def test_a_clean_estate_still_counts_zero():
    out = load("criticalvulnerabilitycount")(reply([detection(2, "Active"), detection(1, "New")]))
    assert value_and_status(out, "criticalVulnerabilityCount") == (0, "success")


def test_a_fixed_critical_is_not_an_open_one():
    out = load("criticalvulnerabilitycount")(
        reply([detection(5, "FIXED", last_fixed="2026-01-20T07:11:13Z")]))
    assert value_and_status(out, "criticalVulnerabilityCount") == (0, "success")


@pytest.mark.parametrize("status", ["Fixed", "FIXED", "fixed"])
def test_a_fully_patched_estate_reads_100_percent_in_every_casing(status):
    out = load("patchcompliancepercentage")(
        reply([detection(3, status, last_fixed="2026-01-20T07:11:13Z")] * 10))
    assert value_and_status(out, "patchCompliancePercentage") == ("100", "success")


def test_an_unpatched_estate_still_reads_zero_percent():
    out = load("patchcompliancepercentage")(reply([detection(3, "Active")] * 10))
    assert value_and_status(out, "patchCompliancePercentage") == ("0", "success")


@pytest.mark.parametrize("status", ["Fixed", "FIXED"])
def test_remediation_time_is_measured_in_every_casing(status):
    out = load("meantimetoremediatecritical")(
        reply([detection(5, status, last_fixed="2026-01-20T07:11:13Z")] * 3))
    assert value_and_status(out, "meanTimeToRemediateCritical") == ("10", "success")


def test_slow_remediation_still_fails():
    out = load("meantimetoremediatecritical")(
        reply([detection(5, "FIXED", last_fixed="2026-06-10T07:11:13Z")] * 3))
    value, status = value_and_status(out, "meanTimeToRemediateCritical")
    assert int(value) > 30 and status == "success"


def test_a_status_that_is_not_a_string_does_not_raise():
    out = load("criticalvulnerabilitycount")(reply([{"SEVERITY": "5", "STATUS": None},
                                                    {"SEVERITY": "5"}]))
    assert value_and_status(out, "criticalVulnerabilityCount") == (0, "success")


# --- F-ASM-24: a truncated host list is a sample, not the estate ----------------------------

TRUNCATED = {
    "criticalvulnerabilitycount": ("criticalVulnerabilityCount", [detection(5, "ACTIVE")] * 3),
    "patchcompliancepercentage": ("patchCompliancePercentage",
                                  [detection(3, "Fixed", last_fixed="2026-01-20T07:11:13Z")] * 3),
    "meantimetoremediatecritical": ("meanTimeToRemediateCritical",
                                    [detection(5, "Fixed", last_fixed="2026-01-20T07:11:13Z")] * 3),
    "knownexploitedvulncount": ("knownExploitedVulnCount", [detection(5, "Active")] * 3),
}


@pytest.mark.parametrize("name", sorted(TRUNCATED))
def test_a_truncated_reply_is_not_measured(name):
    key, detections = TRUNCATED[name]
    out = load(name)(reply(detections, truncated=True))
    value, status = value_and_status(out, key)
    assert value is None, f"{key} answered {value!r} over a 1000-host sample"
    assert status == "error"
    errors = out["additionalInfo"]["dataCollection"]["errors"]
    assert errors and "1980" in errors[0] and key in errors[0]


@pytest.mark.parametrize("name", sorted(TRUNCATED))
def test_the_same_body_under_the_engine_envelope_is_not_measured(name):
    key, detections = TRUNCATED[name]
    body = {"data": reply(detections, truncated=True),
            "validation": {"status": "passed", "errors": [], "warnings": []}}
    assert value_and_status(load(name)(body), key) == (None, "error")


@pytest.mark.parametrize("name", sorted(TRUNCATED))
def test_an_untruncated_reply_is_still_measured(name):
    key, detections = TRUNCATED[name]
    value, status = value_and_status(load(name)(reply(detections)), key)
    assert value is not None and status == "success"


def test_the_warning_is_recognised_as_a_list_and_by_its_text_alone():
    """xmltodict gives a dict for one WARNING and a list for several, and a platform that
    reworded the text would still carry CODE 1980 -- and one that renumbered the code would
    still say the limit was exceeded. Either alone is enough."""
    body = reply([detection(5, "ACTIVE")] * 3, truncated=True)
    body["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"] = [
        {"CODE": "1980", "TEXT": "", "URL": ""}]
    assert value_and_status(load("criticalvulnerabilitycount")(body),
                            "criticalVulnerabilityCount") == (None, "error")
    body["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"] = {
        "TEXT": "1000 record limit exceeded. Use URL to get next batch of results."}
    assert value_and_status(load("criticalvulnerabilitycount")(body),
                            "criticalVulnerabilityCount") == (None, "error")


def test_an_unrelated_warning_does_not_suppress_a_real_measurement():
    body = reply([detection(5, "ACTIVE")] * 12)
    body["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["WARNING"] = {
        "CODE": "1234", "TEXT": "something else entirely"}
    assert value_and_status(load("criticalvulnerabilitycount")(body),
                            "criticalVulnerabilityCount") == (12, "success")


# --- the lanes this branch leaves alone, pinned so a later edit has to mean it ---------------

def test_an_empty_body_is_still_graded_which_is_a_separate_finding():
    """F-ASM-02 / F-ASM-05. An empty read still answers a number under a success status, so a
    customer is still told 0 criticals and 100 % patched from a body that said nothing. Nothing
    on this branch changes it; this test exists so that a later branch has to change it
    deliberately rather than by accident."""
    assert value_and_status(load("criticalvulnerabilitycount")({}),
                            "criticalVulnerabilityCount") == (0, "success")
    assert value_and_status(load("patchcompliancepercentage")({}),
                            "patchCompliancePercentage") == ("100", "success")


def test_a_body_whose_reads_raise_is_still_graded_which_is_a_separate_finding():
    """F-ASM-05, and the reason `truncated_read` swallows its own read errors: the poisoned lane
    must come out of this branch byte-for-byte as it went in."""

    class Poisoned(dict):
        def get(self, *a, **kw):
            raise RuntimeError("poisoned body")

    assert value_and_status(load("criticalvulnerabilitycount")(Poisoned()),
                            "criticalVulnerabilityCount") == (0, "success")
