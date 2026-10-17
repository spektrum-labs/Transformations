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


def test_free_level_fails():
    assert verdict(dict(ACCOUNT, subscription_level="Free")) is False
    assert verdict(dict(ACCOUNT, subscription_level=" free ")) is False


def test_no_readable_subscription_level_is_not_evaluated():
    """A level that is null, empty, blank or not text says nothing about the subscription: None plus a
    data-collection error (Not evaluated), never a failed or a passed check."""
    for level in [None, "", "   ", 5, True, ["Diamond"], {"a": 1}]:
        out = LICENCE.transform(dict(ACCOUNT, subscription_level=level))
        assert out["transformedResponse"]["confirmedLicensePurchased"] is None, level
        collection = out["additionalInfo"]["dataCollection"]
        assert collection["status"] == "error" and collection["errors"], level


def test_no_evidence_is_not_evaluated():
    """An error, an empty or an unrecognised body is not an account: None plus a data-collection
    error (shown as Not evaluated), never a failed check."""
    bodies = [{}, None, "{}", "", {"error": True, "message": "HTTP 401: Unauthorized"},
              {k: v for k, v in ACCOUNT.items() if k != "subscription_level"}, {"hello": "world"}]
    for body in bodies:
        out = LICENCE.transform(body)
        assert out["transformedResponse"]["confirmedLicensePurchased"] is None, body
        collection = out["additionalInfo"]["dataCollection"]
        assert collection["status"] == "error" and collection["errors"], body


def test_unreadable_end_date_is_not_evaluated():
    out = LICENCE.transform(dict(ACCOUNT, subscription_end_date="not a date"))
    assert out["transformedResponse"]["confirmedLicensePurchased"] is None
    assert out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_reasons_are_fixed_text_never_exception_or_vendor_text():
    secret = "SECRET-VENDOR-VALUE-123"
    bodies = [dict(ACCOUNT, subscription_end_date=secret),
              "{not json " + secret,
              dict(ACCOUNT, subscription_level=secret, subscription_end_date=object())]
    for body in bodies:
        out = LICENCE.transform(body)
        text = repr(out)
        assert secret not in text
        for fragment in ("Invalid isoformat", "Expecting", "object has no attribute", "TypeError", "ValueError"):
            assert fragment not in text, (fragment, text)
        assert out["transformedResponse"]["confirmedLicensePurchased"] is None
        assert out["additionalInfo"]["dataCollection"]["status"] == "error"
