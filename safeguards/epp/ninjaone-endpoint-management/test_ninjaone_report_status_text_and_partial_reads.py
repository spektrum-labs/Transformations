"""NinjaOne antivirus-status checks: definition-status text is matched loosely, and a partial read is not a total.

Status text. The report's definitionStatus is matched after lower-casing and dropping spaces, hyphens and
underscores, so "Out-of-Date", " out-of-date " and "Out of Date" are one status, and so are "Up-to-Date", "up to date"
and "UP-TO-DATE". A status that is neither (Unknown, Outdated, a made-up word) stays Unknown. Before, a spelling variant of
Out-of-Date fell into Unknown, so isSignatureUpToDate read True beside one Up-to-Date device, and a variant of Up-to-Date
counted as out of date on isEPPMisconfigured.

Partial reads. A report whose cursor.count is above the rows received, a cursor that names itself and gives no count, a
next-page marker or a truncation flag is only part of the fleet. A verdict that rests on the absence of a row (no
Out-of-Date device, no device left off, no misconfigured device, no active product) is then None with a data-collection
error. A verdict proven by a row that WAS read stays (an Out-of-Date row keeps isSignatureUpToDate False; an active
product keeps isEPPDeployed True), with its counts left unknown. The live "cursor": [] is a complete read. Synthetic data."""
import importlib.util
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
NOW = time.time()

SIG = "isSignatureUpToDate"
DEP = "isEPPDeployed"
ENA = "isEPPEnabled"
EDR = "isEDRDeployed"
MIS = "isEPPMisconfigured"
ALL = [SIG, DEP, ENA, EDR, MIS]
EDR_PRODUCT = "CrowdStrike Falcon Sensor"


def run(name, body):
    spec = importlib.util.spec_from_file_location("nj_report_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


def row(did, state="ON", status="Up-to-Date", product="Defender"):
    return {"deviceId": did, "productName": product, "productState": state, "definitionStatus": status, "timestamp": NOW}


def cursor(count, name="c1"):
    return {"name": name, "offset": 0, "count": count, "expires": 0}


def value(name, out):
    return out["transformedResponse"][name]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def not_evaluated(out):
    return collection(out)["status"] == "error" and len(collection(out)["errors"]) > 0


OUT_VARIANTS = ["Out-of-Date", "out-of-date", " Out-of-Date ", "Out of Date", "OUT-OF-DATE", "out_of_date", "Out-Of-Date",
                "outofdate", "\tOut-of-Date\n"]
UP_VARIANTS = ["Up-to-Date", "up-to-date", " Up-to-Date ", "Up to Date", "UP-TO-DATE", "up_to_date", "Up-To-Date", "uptodate"]


class TestOutOfDateAnyWayItIsSpelled:
    @pytest.mark.parametrize("variant", OUT_VARIANTS)
    def test_a_variant_beside_an_up_to_date_device_fails_the_signature_check(self, variant):
        out = run(SIG, {"results": [row(1), row(2, status=variant)]})
        assert value(SIG, out) is False
        assert out["transformedResponse"]["outOfDateCount"] == 1
        assert not not_evaluated(out)

    @pytest.mark.parametrize("variant", OUT_VARIANTS)
    def test_a_variant_alone_fails_the_signature_check(self, variant):
        out = run(SIG, {"results": [row(1, status=variant)]})
        assert value(SIG, out) is False
        assert not not_evaluated(out)

    @pytest.mark.parametrize("variant", OUT_VARIANTS)
    def test_a_variant_is_an_outdated_definition_on_the_misconfigured_check(self, variant):
        out = run(MIS, {"results": [row(1, status=variant)]})
        assert value(MIS, out) is True


class TestUpToDateAnyWayItIsSpelled:
    @pytest.mark.parametrize("variant", UP_VARIANTS)
    def test_a_variant_passes_the_signature_check(self, variant):
        out = run(SIG, {"results": [row(1, status=variant), row(2, status=variant)]})
        assert value(SIG, out) is True
        assert out["transformedResponse"]["upToDateCount"] == 2
        assert out["transformedResponse"]["unknownStatusCount"] == 0

    @pytest.mark.parametrize("variant", UP_VARIANTS)
    def test_a_variant_is_a_current_definition_on_the_misconfigured_check(self, variant):
        out = run(MIS, {"results": [row(1, status=variant)]})
        assert value(MIS, out) is False

    @pytest.mark.parametrize("word", ["Unknown", "Outdated", "Up-to-Date-ish", "Out-of-Date soon", "Current", ""])
    def test_any_other_status_stays_unknown_on_the_signature_check(self, word):
        out = run(SIG, {"results": [row(1), row(2, status=word or "N/A")]})
        assert value(SIG, out) is True
        assert out["transformedResponse"]["unknownStatusCount"] == 1
        assert out["transformedResponse"]["upToDateCount"] == 1

    @pytest.mark.parametrize("word", ["Unknown", "Outdated", "Current"])
    def test_any_other_status_is_still_an_outdated_definition_on_the_misconfigured_check(self, word):
        assert value(MIS, run(MIS, {"results": [row(1, status=word)]})) is True


# Per check: (rows, answer) for a verdict that rests on the absence of a row, and (rows, answer) for a verdict a row proves.
BENIGN_AND_PROVEN = {
    SIG: ([row(1), row(2)], True, [row(1), row(2, status="Out-of-Date")], False),
    DEP: ([row(1, state="OFF"), row(2, state="OFF")], False, [row(1, state="OFF"), row(2)], True),
    ENA: ([row(1), row(2)], True, [row(1), row(2, state="OFF")], False),
    EDR: ([row(1, product="Defender"), row(2, product="Defender")], False, [row(1, product=EDR_PRODUCT), row(2)], True),
    MIS: ([row(1), row(2)], False, [row(1), row(2, state="OFF")], True),
}
MARKERS = [
    ("cursor count above the rows", {"cursor": cursor(40)}),
    ("cursor count as text above the rows", {"cursor": cursor("40")}),
    ("cursor name and no count", {"cursor": {"name": "c1"}}),
    ("cursor name and a null count", {"cursor": {"name": "c1", "offset": 0, "count": None, "expires": 0}}),
    ("cursor text", {"cursor": "after-2"}),
    ("next page marker", {"next": "page-2"}),
    ("truncated flag", {"truncated": True}),
    ("more flag as text", {"hasMore": "true"}),
]
COMPLETE_MARKERS = [
    ("the live empty cursor list", {"cursor": []}),
    ("a cursor count equal to the rows", {"cursor": cursor(2)}),
    ("no cursor at all", {}),
    ("a null cursor", {"cursor": None}),
    ("a cursor with no name and no count", {"cursor": {"name": None, "offset": 0, "expires": 0}}),
    ("next marker null", {"next": None}),
    ("truncated false", {"truncated": "false"}),
]


@pytest.mark.parametrize("name", ALL)
class TestAPartialReport:
    @pytest.mark.parametrize("label,marker", MARKERS, ids=[m[0] for m in MARKERS])
    def test_a_verdict_resting_on_missing_rows_reads_none_with_a_data_collection_error(self, name, label, marker):
        rows, _answer, _proof_rows, _proof = BENIGN_AND_PROVEN[name]
        out = run(name, dict({"results": rows}, **marker))
        assert value(name, out) is None
        assert not_evaluated(out)

    @pytest.mark.parametrize("label,marker", MARKERS, ids=[m[0] for m in MARKERS])
    def test_a_verdict_a_seen_row_proves_stays_with_its_counts_unknown(self, name, label, marker):
        _rows, _answer, rows, proof = BENIGN_AND_PROVEN[name]
        out = run(name, dict({"results": rows}, **marker))
        assert value(name, out) is proof
        assert out["transformedResponse"]["partialRead"] is True
        for key, found in out["transformedResponse"].items():
            if key != name and not key.endswith("AtLeast") and isinstance(found, int) and not isinstance(found, bool):
                raise AssertionError("count left in a partial read: %s=%r" % (key, found))
        assert not not_evaluated(out)

    @pytest.mark.parametrize("label,marker", COMPLETE_MARKERS, ids=[m[0] for m in COMPLETE_MARKERS])
    def test_a_complete_read_keeps_the_normal_answer(self, name, label, marker):
        rows, answer, _proof_rows, _proof = BENIGN_AND_PROVEN[name]
        out = run(name, dict({"results": rows}, **marker))
        assert value(name, out) is answer
        assert "partialRead" not in out["transformedResponse"]
        assert not not_evaluated(out)

    def test_a_partial_read_wrapped_in_the_data_envelope_is_still_partial(self, name):
        rows, _answer, _proof_rows, _proof = BENIGN_AND_PROVEN[name]
        body = {"data": {"results": rows, "cursor": cursor(40)}, "validation": {"status": "unknown", "errors": [], "warnings": []}}
        out = run(name, body)
        assert value(name, out) is None
        assert not_evaluated(out)

    def test_an_error_body_stays_none_as_before(self, name):
        out = run(name, {"error": "boom", "cursor": cursor(40)})
        assert value(name, out) is None
        assert not_evaluated(out)


class TestSignatureProofSurvivesAPartialRead:
    def test_an_out_of_date_row_keeps_false_and_reports_the_seen_count_beside_it(self):
        out = run(SIG, {"results": [row(1), row(2, status="out of date"), row(3, status="Unknown")], "cursor": cursor(500)})
        assert value(SIG, out) is False
        result = out["transformedResponse"]
        assert result["outOfDateCount"] is None
        assert result["outOfDateCountAtLeast"] == 1
        assert result["upToDateCount"] is None
        assert result["totalReportingDevices"] is None

    def test_only_up_to_date_rows_on_a_partial_read_is_not_a_pass(self):
        out = run(SIG, {"results": [row(i) for i in range(1, 6)], "cursor": cursor(500)})
        assert value(SIG, out) is None
        assert not_evaluated(out)

    def test_a_partial_read_of_unknown_rows_stays_none(self):
        out = run(SIG, {"results": [row(1, status="Unknown")], "cursor": {"name": "c1"}})
        assert value(SIG, out) is None
        assert not_evaluated(out)
