"""requiredCoveragePercentage: an empty or unreadable device list is Not evaluated, never 100.

Zero eligible devices used to return 100 ("all eligible devices are protected: 0/0"), so a Defender
read that proved nothing passed a coverage requirement. Now: no eligible device, no machine list, a
partial page or an error each give None plus a dataCollection error. A fleet that was read still
answers its real percentage (100 when all are protected, less when some are not). Synthetic data only.
"""
import importlib.util
from pathlib import Path

import pytest

KEY = "requiredCoveragePercentage"


def load():
    spec = importlib.util.spec_from_file_location("rcp_empty", Path(__file__).with_name("requiredcoveragepercentage.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def machine(status="Onboarded"):
    return {"osPlatform": "Windows11", "onboardingStatus": status, "healthStatus": "Active", "isExcluded": False}


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def assert_not_evaluated(out):
    assert out["transformedResponse"][KEY] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])


def test_all_eligible_devices_protected_is_100():
    out = load().transform({"value": [machine(), machine()]})
    assert out["transformedResponse"][KEY] == 100
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_half_the_eligible_devices_protected_is_a_real_fail():
    out = load().transform({"value": [machine(), machine("CanBeOnboarded")]})
    assert out["transformedResponse"][KEY] == 50
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["failReasons"]


@pytest.mark.parametrize("body", [
    {"value": []},
    [],
    {"value": [machine("Unsupported"), machine("InsufficientInfo")]},
    {"value": [{"osPlatform": "Windows11", "onboardingStatus": "Onboarded", "isExcluded": True}]},
], ids=["empty-value", "empty-list", "only-ineligible", "only-excluded"])
def test_no_eligible_device_is_not_evaluated_not_100(body):
    out = load().transform(body)
    assert_not_evaluated(out)
    assert out["transformedResponse"]["eligibleDevicesPercentageofCoverage"] is None


@pytest.mark.parametrize("body", [
    {},
    None,
    "{}",
    {"error": {"code": "Unauthorized", "message": "denied"}},
    {"value": "not-a-list"},
], ids=["empty-object", "none", "empty-json-string", "error-envelope", "value-not-a-list"])
def test_unreadable_body_is_not_evaluated(body):
    assert_not_evaluated(load().transform(body))


def test_partial_page_is_not_evaluated():
    body = {"value": [machine()], "@odata.nextLink": "https://example.invalid/api/machines?$skip=1"}
    assert_not_evaluated(load().transform(body))


def test_failed_validation_is_not_evaluated():
    out = load().transform({"data": {"value": [machine()]}, "validation": {"status": "failed", "errors": ["bad"], "warnings": []}})
    assert_not_evaluated(out)


def test_exception_is_not_evaluated():
    assert_not_evaluated(load().transform(Poisoned()))
