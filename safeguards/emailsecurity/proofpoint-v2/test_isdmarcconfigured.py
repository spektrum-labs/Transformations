"""Proofpoint isDMARCConfigured: the anti_spoofing feature flag is not a DMARC record.

The transform was a copy of the anti-phishing check and answered DMARC from the features body's
anti_spoofing flag. The features body (Proofpoint Essentials GET /api/v1/orgs/{domain}/features) has no
DMARC setting, so that body is now Not evaluated (None plus a dataCollection error). DMARC is read only from
a DNS lookup answer under a DMARC key: the record text is True, a stated absent record is False.
Synthetic data only.
"""
import importlib.util
from pathlib import Path

import pytest

KEY = "isDMARCConfigured"
RECORD = "v=DMARC1; p=reject; rua=mailto:dmarc@example.invalid"


def load():
    spec = importlib.util.spec_from_file_location("proofpoint_v2_isdmarcconfigured", Path(__file__).with_name("isdmarcconfigured.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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


def features(anti_spoofing):
    return {"features": {"anti_spoofing": anti_spoofing, "url_defense": True, "attachment_defense": True}}


@pytest.mark.parametrize("flag", [True, False, "enabled", "disabled", 1, 0], ids=["on", "off", "word-on", "word-off", "one", "zero"])
def test_features_body_is_not_evaluated_whatever_the_anti_spoofing_flag_says(flag):
    assert_not_evaluated(load().transform(features(flag)))


def test_published_dmarc_record_is_true():
    out = load().transform({"DMARC": RECORD, "SPF": "v=spf1 -all", "DKIM": False})
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"]


@pytest.mark.parametrize("absent", [False, "False", "false"], ids=["bool", "str-False", "str-false"])
def test_stated_absent_record_is_a_real_false(absent):
    out = load().transform({"result": {"SPF": "v=spf1 -all", "DKIM": "v=DKIM1; p=abc", "DMARC": absent}})
    assert out["transformedResponse"][KEY] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["failReasons"]


@pytest.mark.parametrize("junk", ["error", "unknown", "", "   ", None, 0, 1, [], {}, "v=spf1 -all"],
                         ids=["error", "unknown", "empty", "blank", "null", "zero", "one", "list", "object", "other-protocol-record"])
def test_unusable_dmarc_value_is_not_evaluated(junk):
    assert_not_evaluated(load().transform({"DMARC": junk}))


@pytest.mark.parametrize("body", [
    {},
    None,
    "{}",
    [],
    {"features": {}},
    {"error": {"code": "unauthorized"}},
    {"errors": ["Authentication failed"]},
    {"unrelated": "json"},
], ids=["empty-object", "none", "empty-json-string", "empty-list", "empty-features", "error-envelope", "errors-list", "unrelated-json"])
def test_empty_or_error_body_is_not_evaluated(body):
    assert_not_evaluated(load().transform(body))


def test_failed_validation_is_not_evaluated():
    out = load().transform({"data": {"DMARC": RECORD}, "validation": {"status": "failed", "errors": ["bad"], "warnings": []}})
    assert_not_evaluated(out)


def test_exception_is_not_evaluated():
    assert_not_evaluated(load().transform(Poisoned()))
