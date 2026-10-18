"""Cloudflare isDNSConfigured: the word "False" is not a configured record, and no answer is Not evaluated.

The DNS helper answers SPF, DKIM and DMARC with the record text, or the bool False when the record is
absent. The transform used bool() on the value, so the string "False" (and any other non-empty string)
counted as a configured record and the aggregate passed. Now each protocol is True (record present),
False (stated absent) or None (no usable answer), and the aggregate is True only when all three are True.
Synthetic data only.
"""
import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).with_name("isdnsconfigured.py")
KEYS = ("isDNSConfigured", "spfConfigured", "dkimConfigured", "dmarcConfigured",
        "isSPFConfigured", "isDKIMConfigured", "isDMARCConfigured")

SPF = "v=spf1 include:_spf.example.invalid -all"
DKIM = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"
DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc@example.invalid"


def load():
    spec = importlib.util.spec_from_file_location("cloudflare_isdnsconfigured_nne", PATH)
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


def helper(spf=SPF, dkim=DKIM, dmarc=DMARC):
    return {"result": {"SPF": spf, "DKIM": dkim, "DMARC": dmarc, "SMTPBanner": "No banner found"}}


def assert_all_none_with_error(out):
    transformed = out["transformedResponse"]
    for key in KEYS:
        assert transformed[key] is None, key
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error"
    assert collection["errors"] and all(isinstance(e, str) and e for e in collection["errors"])


def test_all_three_records_present_is_true():
    out = load().transform(helper())
    assert out["transformedResponse"]["isDNSConfigured"] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


@pytest.mark.parametrize("absent", [False, "False", "false", " FALSE "], ids=["bool", "str-False", "str-false", "str-padded"])
def test_a_record_stated_absent_is_false_whatever_its_spelling(absent):
    out = load().transform(helper(dkim=absent))
    transformed = out["transformedResponse"]
    assert transformed["isDKIMConfigured"] is False
    assert transformed["isSPFConfigured"] is True
    assert transformed["isDMARCConfigured"] is True
    assert transformed["isDNSConfigured"] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_all_three_stated_absent_as_strings_is_false_not_true():
    out = load().transform(helper(spf="False", dkim="False", dmarc="False"))
    transformed = out["transformedResponse"]
    assert transformed["isDNSConfigured"] is False
    assert (transformed["spfConfigured"], transformed["dkimConfigured"], transformed["dmarcConfigured"]) == (False, False, False)


def test_nested_string_false_is_not_enabled():
    body = {"settings": {"emailAuthentication": {"spf": {"enabled": "false"}, "dkim": {"configured": True}, "dmarc": True}}}
    transformed = load().transform(body)["transformedResponse"]
    assert transformed["isSPFConfigured"] is False
    assert transformed["isDNSConfigured"] is False


@pytest.mark.parametrize("junk", ["error", "unknown", "", "   ", None, 0, 1, [], {}, "v=DMARC1; p=none"],
                         ids=["error", "unknown", "empty", "blank", "null", "zero", "one", "list", "object", "other-protocol-record"])
def test_unusable_answer_for_one_protocol_is_not_a_record_and_not_evaluated(junk):
    out = load().transform(helper(spf=junk))
    transformed = out["transformedResponse"]
    assert transformed["isSPFConfigured"] is None
    assert transformed["isDKIMConfigured"] is True
    assert transformed["isDNSConfigured"] is None
    collection = out["additionalInfo"]["dataCollection"]
    assert collection["status"] == "error" and "SPF" in collection["errors"][0]


def test_unknown_protocol_does_not_hide_a_stated_absent_one():
    out = load().transform(helper(spf="error", dmarc=False))
    transformed = out["transformedResponse"]
    assert transformed["isDNSConfigured"] is False
    assert transformed["isSPFConfigured"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


@pytest.mark.parametrize("body", [
    {},
    None,
    "{}",
    [],
    {"result": {}},
    {"error": {"code": "unavailable"}},
    {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}], "result": None},
    {"success": True, "result": []},
    {"unrelated": "json"},
], ids=["empty-object", "none", "empty-json-string", "empty-list", "empty-result", "error-envelope", "cloudflare-auth-error", "empty-records", "unrelated-json"])
def test_empty_or_error_body_is_not_evaluated(body):
    assert_all_none_with_error(load().transform(body))


def test_failed_validation_is_not_evaluated():
    out = load().transform({"data": helper(), "validation": {"status": "failed", "errors": ["bad"], "warnings": []}})
    assert_all_none_with_error(out)


def test_exception_is_not_evaluated():
    assert_all_none_with_error(load().transform(Poisoned()))


def test_zone_records_found_pass_and_missing_ones_are_unknown_not_absent():
    module = load()
    full = {"result": [
        {"type": "TXT", "name": "example.invalid", "content": "v=spf1 -all"},
        {"type": "TXT", "name": "sel._domainkey.example.invalid", "content": DKIM},
        {"type": "TXT", "name": "_dmarc.example.invalid", "content": DMARC},
    ]}
    assert module.transform(full)["transformedResponse"]["isDNSConfigured"] is True

    out = module.transform({"result": full["result"][:2]})
    transformed = out["transformedResponse"]
    assert transformed["isSPFConfigured"] is True
    assert transformed["isDMARCConfigured"] is None
    assert transformed["isDNSConfigured"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"
