"""Keepit confirmedLicensePurchased answers a boolean, or None when the account could not be read.

The requirement compares the key with isEquals true, so the old "confirmed" / "unconfirmed" strings
could never be satisfied. The body is the xmltodict form of Keepit's <user> element
(https://developers.keepit.com/api/accounts/~schemas#user-v0). Synthetic data only.
"""
import importlib.util
import json
import pathlib

import pytest

HERE = pathlib.Path(__file__).resolve().parent
KEY = "confirmedLicensePurchased"


def load():
    spec = importlib.util.spec_from_file_location("keepit_license", HERE / "confirmedlicensepurchased.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def account(**overrides):
    user = {"enabled": "true", "created": "2026-01-01T10:00:00Z",
            "product": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "subscribed": "true"}
    user.update(overrides)
    return {"user": {k: v for k, v in user.items() if v is not None}}


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


def test_enabled_subscribed_account_with_product_is_boolean_true():
    out = load().transform(account())
    assert out["transformedResponse"][KEY] is True
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert out["additionalInfo"]["evaluation"]["passReasons"]


@pytest.mark.parametrize("overrides,expected_reason", [
    ({"subscribed": "false"}, "not subscribed"),
    ({"enabled": "false"}, "not enabled"),
    ({"deletion-deadline": "2026-12-31T00:00:00Z"}, "scheduled for deletion"),
], ids=["not-subscribed", "not-enabled", "deletion-deadline"])
def test_account_read_and_stated_negative_is_a_real_false(overrides, expected_reason):
    out = load().transform(account(**overrides))
    assert out["transformedResponse"][KEY] is False
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"
    assert expected_reason in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("overrides", [{"subscribed": None}, {"enabled": None}, {"product": None}, {"product": ""}],
                         ids=["subscribed-unstated", "enabled-unstated", "product-unstated", "product-empty"])
def test_unstated_field_is_not_evaluated(overrides):
    assert_not_evaluated(load().transform(account(**overrides)))


@pytest.mark.parametrize("body", [
    {},
    None,
    "{}",
    "",
    {"user": None},
    {"user": "not-a-dict"},
    {"error": {"code": "401", "message": "unauthorized"}},
    "<user><enabled>true</enabled></user>",
], ids=["empty-object", "none", "empty-json-string", "empty-string", "user-null", "user-not-dict", "error-envelope", "raw-xml"])
def test_empty_or_unreadable_body_is_not_evaluated(body):
    assert_not_evaluated(load().transform(body))


def test_exception_is_not_evaluated():
    assert_not_evaluated(load().transform(Poisoned()))


def test_json_string_and_wrapped_bodies_read_the_same_account():
    module = load()
    assert module.transform(json.dumps(account()))["transformedResponse"][KEY] is True
    assert module.transform({"response": account(subscribed="false")})["transformedResponse"][KEY] is False


def test_never_returns_the_old_strings():
    module = load()
    for body in (account(), account(subscribed="false"), {}):
        assert module.transform(body)["transformedResponse"][KEY] not in ("confirmed", "unconfirmed")
