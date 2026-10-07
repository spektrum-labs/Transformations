"""KnowBe4 confirmedLicensePurchased on the documented GET /v1/account body, whose
subscription_end_date is a date only ("2021-03-06"). Before the fix every such body read false
("can't compare offset-naive and offset-aware datetimes")."""
import importlib.util
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("kb4_licence", HERE / "confirmedlicensepurchased.py")
LICENCE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(LICENCE)

ACCOUNT = {"name": "KB4-Demo", "type": "paid", "domains": ["kb4-demo.test"], "admins": [],
           "subscription_level": "Diamond", "subscription_end_date": "2099-03-06", "number_of_seats": 25}


def verdict(body):
    return LICENCE.transform(body)["transformedResponse"]["confirmedLicensePurchased"]


def test_date_only_future_passes():
    assert verdict(ACCOUNT) is True


def test_date_only_past_fails():
    assert verdict(dict(ACCOUNT, subscription_end_date="2021-03-06")) is False


def test_full_timestamp_still_parsed():
    assert verdict(dict(ACCOUNT, subscription_end_date="2099-03-06T00:00:00Z")) is True


def test_free_or_missing_level_fails():
    assert verdict(dict(ACCOUNT, subscription_level="Free")) is False
    assert verdict({k: v for k, v in ACCOUNT.items() if k != "subscription_level"}) is False


def test_no_evidence_fails():
    for body in [{}, None, "{}", {"error": True, "message": "HTTP 401: Unauthorized"}]:
        assert verdict(body) is False
