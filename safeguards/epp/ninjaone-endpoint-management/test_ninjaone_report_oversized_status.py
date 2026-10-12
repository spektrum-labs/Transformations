"""NinjaOne antivirus-status checks: an HTTP status made of thousands of digits does not raise.

http_error_status turns a status sent as text ("500") into a number. int() refuses a digit string past the interpreter's
limit (4300 digits). A digit string longer than nine digits is not an HTTP status, so it is ignored and the report is
scored as usual. Real error statuses ("500", " 403 ") still read Not evaluated. Synthetic data only."""
import importlib.util
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
NOW = time.time()
NAMES = ["isSignatureUpToDate", "isEPPDeployed", "isEPPEnabled", "isEDRDeployed", "isEPPMisconfigured"]


def run(name, body):
    spec = importlib.util.spec_from_file_location("nj_report_oversized_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


def body(**extra):
    rows = [{"deviceId": i, "productName": "CrowdStrike Falcon Sensor", "productState": "ON",
             "definitionStatus": "Up-to-Date", "timestamp": NOW} for i in (1, 2)]
    return dict({"results": rows}, **extra)


def errored(out):
    collection = out["additionalInfo"]["dataCollection"]
    return collection["status"] == "error" and len(collection["errors"]) > 0


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("field", ["status", "statusCode", "status_code"])
@pytest.mark.parametrize("status", ["9" * 5000, "5" * 4301, "5" * 10, " " + "4" * 4400 + " "], ids=["9x5000", "5x4301", "5x10", "padded"])
def test_a_status_of_thousands_of_digits_does_not_raise_and_the_report_is_scored(name, field, status):
    out = run(name, body(**{field: status}))
    assert not errored(out)
    assert out["transformedResponse"][name] is not None


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("status", ["500", " 403 ", "400", 502])
def test_a_real_error_status_still_reads_not_evaluated(name, status):
    out = run(name, body(status=status))
    assert out["transformedResponse"][name] is None
    assert errored(out)


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("status", ["200", "204", "399", "", "ok", True, None])
def test_a_status_that_is_not_an_error_does_not_stop_the_read(name, status):
    out = run(name, body(status=status))
    assert out["transformedResponse"][name] is not None
    assert not errored(out)
