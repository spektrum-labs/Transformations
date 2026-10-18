"""KnowBe4 confirmedLicensePurchased reads the account body (type, subscription_end_date).

Synthetic body in the shape GET /v1/account returns; every identifying value is invented.
Before this fix the transform looked only for `licensePurchased`, found none, and reported a
paid, current subscription as "License has not been purchased".
"""
import importlib.util
import json
import pathlib
from datetime import datetime, timedelta

import pytest

HERE = pathlib.Path(__file__).parent
KEY = "confirmedLicensePurchased"


def run(body):
    spec = importlib.util.spec_from_file_location("knowbe4_license", HERE / "confirmedlicensepurchased.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform(body)


def day(offset):
    return (datetime.utcnow() + timedelta(days=offset)).strftime("%Y-%m-%d")


def account(**overrides):
    body = {"name": "Example Org", "type": "paid", "domains": ["example.com"],
            "admins": [{"id": 1, "first_name": "Ada", "last_name": "Admin", "email": "admin@example.com"}],
            "subscription_level": "SAT Advanced", "subscription_end_date": day(400),
            "number_of_seats": "250", "current_risk_score": "30.1"}
    body.update(overrides)
    return body


def test_paid_current_subscription_is_true():
    out = run(account())
    assert out["transformedResponse"][KEY] is True
    assert "SAT Advanced" in out["additionalInfo"]["evaluation"]["passReasons"][0]


def test_paid_subscription_ending_today_is_true():
    assert run(account(subscription_end_date=day(0)))["transformedResponse"][KEY] is True


def test_expired_subscription_is_false():
    out = run(account(subscription_end_date=day(-1)))
    assert out["transformedResponse"][KEY] is False
    assert "ended on" in out["additionalInfo"]["evaluation"]["failReasons"][0]


@pytest.mark.parametrize("kind", ["trial", "expired", "cancelled"])
def test_non_paid_account_type_is_false(kind):
    assert run(account(type=kind))["transformedResponse"][KEY] is False


@pytest.mark.parametrize("body", [{}, None, "{}", [], {"error": "Unauthorized"},
                                  {"message": "Integration execution error: HTTP 401"},
                                  {"name": "Example Org"},
                                  account(subscription_end_date="not-a-date")],
                         ids=lambda b: json.dumps(b)[:40])
def test_empty_error_or_unrecognised_body_is_not_evaluated(body):
    out = run(body)
    assert out["transformedResponse"][KEY] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_string_body_is_parsed():
    assert run(json.dumps(account()))["transformedResponse"][KEY] is True


def test_legacy_license_purchased_key_still_honoured():
    assert run({"licensePurchased": True})["transformedResponse"][KEY] is True
    assert run({"licensePurchased": False})["transformedResponse"][KEY] is False
