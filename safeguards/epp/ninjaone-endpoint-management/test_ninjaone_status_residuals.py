"""NinjaOne antivirus-status checks: two residual gaps in the fail-closed rules.

  1. isSignatureUpToDate: when the judged devices carry a named product but no product reports a definitionStatus,
     signature currency cannot be confirmed. That is Not evaluated (None), never False. A fleet where no device has a
     product at all (productName NONE) is still a real answer and is unchanged.
  2. An HTTP status sent as a string ("500", " 403 ") is an error reply exactly like the number. Without this a reply
     that says "500" beside product rows would still be measured.
Synthetic data only."""
import importlib.util
import pathlib
import time

import pytest

HERE = pathlib.Path(__file__).resolve().parent
NOW = time.time()

FILES = [
    "endpointOperationalStatusUnprotectedCount",
    "isEDRDeployed",
    "isEPPConfigured",
    "isEPPDeployed",
    "isEPPEnabled",
    "isEPPMisconfigured",
    "isSignatureUpToDate",
    "requiredCoveragePercentage",
]


def run(name, body):
    spec = importlib.util.spec_from_file_location("nj_resid_" + name, HERE / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


def value(name, out):
    return out["transformedResponse"][name]


def not_evaluated(out):
    return out["additionalInfo"]["dataCollection"]["status"] == "error"


def row(did, product="Defender", state="ON", definition="Up-to-Date"):
    out = {"deviceId": did, "productName": product, "productState": state, "timestamp": NOW}
    if definition is not None:
        out["definitionStatus"] = definition
    return out


def body(rows, **extra):
    """A report body; the device list beside it is exactly the devices the rows mention."""
    ids = []
    for r in rows:
        if r["deviceId"] not in ids:
            ids.append(r["deviceId"])
    out = {"results": rows, "devices": [{"id": i, "nodeClass": "WINDOWS_WORKSTATION", "lastContact": NOW} for i in ids]}
    out.update(extra)
    return out


# 1. a named product with no definitionStatus
@pytest.mark.parametrize("missing", [None, "", "  "])
def test_named_products_with_no_definition_status_read_none(missing):
    rows = [row(1, definition=missing), row(2, definition=missing)]
    out = run("isSignatureUpToDate", body(rows))
    assert value("isSignatureUpToDate", out) is None
    assert not_evaluated(out)


def test_a_named_product_with_no_definition_status_key_reads_none():
    rows = [{"deviceId": 1, "productName": "Defender", "productState": "ON", "timestamp": NOW}]
    out = run("isSignatureUpToDate", body(rows))
    assert value("isSignatureUpToDate", out) is None
    assert not_evaluated(out)


def test_the_reason_says_the_product_did_not_report_a_definition_status():
    out = run("isSignatureUpToDate", body([row(1, definition=None)]))
    reasons = " ".join(out["additionalInfo"]["dataCollection"]["errors"])
    assert "definition status" in reasons


def test_one_reporting_device_still_decides_the_answer():
    rows = [row(1, definition=None), row(2, definition="Up-to-Date")]
    out = run("isSignatureUpToDate", body(rows))
    assert value("isSignatureUpToDate", out) is True
    assert not not_evaluated(out)


def test_an_out_of_date_device_still_fails():
    rows = [row(1, definition=None), row(2, definition="Out-of-Date")]
    out = run("isSignatureUpToDate", body(rows))
    assert value("isSignatureUpToDate", out) is False


def test_a_fleet_with_no_product_at_all_is_unchanged():
    rows = [row(1, product="NONE", state=None, definition=None), row(2, product="NONE", state=None, definition=None)]
    out = run("isSignatureUpToDate", body(rows))
    assert value("isSignatureUpToDate", out) is False
    assert not not_evaluated(out)


def test_a_mixed_fleet_of_no_product_and_named_products_without_a_status_reads_none():
    rows = [row(1, product="NONE", state=None, definition=None), row(2, definition=None)]
    out = run("isSignatureUpToDate", body(rows))
    assert value("isSignatureUpToDate", out) is None
    assert not_evaluated(out)


# 2. a status sent as a string
STRING_CODES = ["500", "403", "400", " 503 ", "401"]


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("field", ["status", "statusCode", "status_code"])
@pytest.mark.parametrize("code", STRING_CODES)
def test_a_string_http_error_status_beside_rows_is_not_evaluated(name, field, code):
    out = run(name, body([row(1), row(2)], **{field: code}))
    assert value(name, out) is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("code", STRING_CODES)
def test_a_string_http_error_status_inside_a_wrapper_is_not_evaluated(name, code):
    inner = body([row(1), row(2)], status=code)
    out = run(name, {"apiResponse": inner})
    assert value(name, out) is None
    assert not_evaluated(out)


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("code", ["200", "201", "204", "ok", "", "abc", None])
def test_a_string_success_or_unrelated_status_is_not_an_error(name, code):
    out = run(name, body([row(1), row(2)], status=code))
    assert value(name, out) is not None
    assert not not_evaluated(out)


@pytest.mark.parametrize("code", ["500", "403"])
def test_a_string_error_status_on_the_device_list_makes_it_unreadable(code):
    b = body([row(1), row(2)])
    b["devices"] = {"data": b["devices"], "status": code}
    out = run("isEPPConfigured", b)
    assert value("isEPPConfigured", out) is None
    assert not_evaluated(out)


# 3. a status made of characters that look like digits but that int() cannot read
# str.isdigit() is True for these (superscripts, circled digits); int() raises ValueError on them. A status such as
# this is not an HTTP error status, so it must neither raise out of transform nor be read as an error.
NON_DECIMAL_DIGITS = ["²", "³", "⁵⁰⁰", "①", " ² "]


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("field", ["status", "statusCode", "status_code"])
@pytest.mark.parametrize("code", NON_DECIMAL_DIGITS)
def test_a_status_of_non_decimal_digits_does_not_raise_and_is_not_an_error(name, field, code):
    out = run(name, body([row(1), row(2)], **{field: code}))
    assert value(name, out) is not None
    assert not not_evaluated(out)


@pytest.mark.parametrize("name", FILES)
@pytest.mark.parametrize("code", NON_DECIMAL_DIGITS)
def test_a_status_of_non_decimal_digits_inside_a_wrapper_does_not_raise(name, code):
    out = run(name, {"apiResponse": body([row(1), row(2)], status=code)})
    assert value(name, out) is not None
    assert not not_evaluated(out)


@pytest.mark.parametrize("code", NON_DECIMAL_DIGITS)
def test_a_status_of_non_decimal_digits_on_the_device_list_does_not_raise(code):
    b = body([row(1), row(2)])
    b["devices"] = {"data": b["devices"], "status": code}
    out = run("isEPPConfigured", b)
    assert value("isEPPConfigured", out) is not None
    assert not not_evaluated(out)


@pytest.mark.parametrize("name", FILES)
def test_a_status_written_in_other_decimal_digits_is_read_as_the_number(name):
    """Arabic-Indic digits are decimal digits: this is 500, an error."""
    out = run(name, body([row(1), row(2)], status="٥٠٠"))
    assert value(name, out) is None
    assert not_evaluated(out)
