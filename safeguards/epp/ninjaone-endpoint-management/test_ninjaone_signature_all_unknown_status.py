"""NinjaOne isSignatureUpToDate: a pass needs at least one device that reports Up-to-Date.

The check reads the definitionStatus each antivirus product reports. "Out-of-Date" fails it. "Up-to-Date" is the only
status that shows signatures are current. A product that reports "Unknown" (or any other status that is not one of those
two) has not said its signatures are current, so a fleet where every reporting device says Unknown shows nothing: the check
reads None (Not evaluated, with a data-collection error), never True. One Up-to-Date device still passes beside Unknown
ones, and an Out-of-Date device still fails whatever else reports. Synthetic data only."""
import importlib.util
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
NOW = time.time()
KEY = "isSignatureUpToDate"


def run(body):
    spec = importlib.util.spec_from_file_location("nj_signature_unknown", HERE / (KEY + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


def row(did, status):
    return {"deviceId": did, "productName": "Defender", "productState": "ON", "definitionStatus": status, "timestamp": NOW}


def value(out):
    return out["transformedResponse"][KEY]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def not_evaluated(out):
    return collection(out)["status"] == "error" and len(collection(out)["errors"]) > 0


@pytest.mark.parametrize("status", ["Unknown", "unknown", "N/A", "Pending", "Scanning"])
class TestEveryReportingDeviceWithoutAKnownStatus:
    def test_one_device_is_not_evaluated(self, status):
        out = run({"results": [row(1, status)]})
        assert value(out) is None
        assert not_evaluated(out)

    def test_many_devices_are_not_evaluated(self, status):
        out = run({"results": [row(i, status) for i in range(1, 8)]})
        assert value(out) is None
        assert not_evaluated(out)
        assert out["transformedResponse"]["unknownStatusCount"] == 7
        assert out["transformedResponse"]["upToDateCount"] == 0

    def test_an_up_to_date_device_beside_them_is_a_pass(self, status):
        out = run({"results": [row(1, status), row(2, "Up-to-Date")]})
        assert value(out) is True
        assert not not_evaluated(out)

    def test_an_out_of_date_device_beside_them_is_a_proven_fail(self, status):
        out = run({"results": [row(1, status), row(2, "Out-of-Date")]})
        assert value(out) is False
        assert not not_evaluated(out)


class TestUnchangedAnswers:
    def test_all_up_to_date_passes(self):
        out = run({"results": [row(i, "Up-to-Date") for i in range(1, 4)]})
        assert value(out) is True
        assert not not_evaluated(out)

    def test_all_out_of_date_fails(self):
        out = run({"results": [row(i, "Out-of-Date") for i in range(1, 4)]})
        assert value(out) is False
        assert not not_evaluated(out)

    def test_one_up_to_date_and_unknowns_passes_and_counts_the_unknowns(self):
        out = run({"results": [row(1, "Up-to-Date"), row(2, "Unknown"), row(3, "Unknown")]})
        assert value(out) is True
        assert out["transformedResponse"]["upToDateCount"] == 1
        assert out["transformedResponse"]["unknownStatusCount"] == 2

    def test_the_not_evaluated_reason_says_nothing_confirmed_the_signatures_are_current(self):
        out = run({"results": [row(1, "Unknown")]})
        reason = collection(out)["errors"][0]
        assert "Unknown" in reason
        assert out["additionalInfo"]["evaluation"]["passReasons"] == []
