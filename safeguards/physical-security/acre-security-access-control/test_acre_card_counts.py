"""acre card counts: a positive count is proof, a zero needs a complete read of readable cards, anything else is None."""
import importlib.util
import os
from datetime import datetime, timedelta, timezone

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("acre_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def when(days):
    """A .NET-style timestamp this many days from now (negative: in the past)."""
    t = datetime.now(timezone.utc) + timedelta(days=days)
    return t.strftime("%Y-%m-%dT%H:%M:%S") + ".1234567Z"


def card(n, expires=None, exempt=False, disabled=False, with_exempt_field=True):
    c = {"Key": "card-" + str(n), "DisplayCardNumber": str(1000 + n), "IsDisabled": disabled, "ExpiresOn": expires if expires is not None else when(90)}
    if with_exempt_field:
        c["AntiPassbackExempt"] = exempt
    return c


def person(i, cards):
    return {"CommonName": "Person " + str(i), "Key": "person-" + str(i), "CardAssignments": cards}


def body(people, truncated=False):
    inner = {"people": people}
    if truncated:
        inner["paginationTruncated"] = True
    return {"data": {"apiResponse": inner}, "validation": {"status": "skipped", "errors": [], "warnings": []}}


EXPIRED = ("expiredButActiveCardCount", "ExpiresOn")
EXEMPT = ("antiPassbackExemptCardCount", "AntiPassbackExempt")


def run(key, payload):
    return load(key)(payload)


def value(key, payload):
    return run(key, payload)["transformedResponse"][key]


def not_evaluated(key, payload):
    out = run(key, payload)
    return out["transformedResponse"][key] is None and out["additionalInfo"]["dataCollection"]["status"] == "error"


def test_expired_enabled_cards_are_counted():
    people = [person(1, [card(1, when(-5)), card(2, when(30))]), person(2, [card(3, when(-400)), card(4, when(-1), disabled=True)])]
    out = run("expiredButActiveCardCount", body(people))
    assert out["transformedResponse"]["expiredButActiveCardCount"] == 2
    assert out["transformedResponse"]["enabledCardCount"] == 3
    assert out["additionalInfo"]["dataCollection"]["status"] == "success"


def test_no_expired_card_is_zero():
    people = [person(1, [card(1, when(10)), card(2, when(400))])]
    assert value("expiredButActiveCardCount", body(people)) == 0


def test_flipping_an_expiry_changes_the_count():
    assert value("expiredButActiveCardCount", body([person(1, [card(1, when(10))])])) == 0
    assert value("expiredButActiveCardCount", body([person(1, [card(1, when(-10))])])) == 1


def test_never_expires_is_not_expired():
    never = ["0001-01-01T00:00:00Z", "9999-12-31T23:59:59.9999999Z", None, ""]
    people = [person(1, [card(i, never[i]) if never[i] is not None else {"Key": "c" + str(i), "IsDisabled": False} for i in range(4)])]
    assert value("expiredButActiveCardCount", body(people)) == 0


def test_an_unreadable_expiry_is_never_scored_beside_a_count():
    people = [person(1, [card(1, "next tuesday")])]
    assert not_evaluated("expiredButActiveCardCount", body(people))
    # one expired card plus an unreadable date is only "at least 1": an inclusive lessThan would pass on it
    people = [person(1, [card(1, "next tuesday"), card(2, when(-3))])]
    assert not_evaluated("expiredButActiveCardCount", body(people))
    assert value("expiredButActiveCardCount", body([person(1, [card(2, when(-3))])])) == 1


def test_exempt_enabled_cards_are_counted():
    people = [person(1, [card(1, exempt=True), card(2)]), person(2, [card(3, exempt=True), card(4, exempt=True, disabled=True)])]
    out = run("antiPassbackExemptCardCount", body(people))
    assert out["transformedResponse"]["antiPassbackExemptCardCount"] == 2
    assert out["transformedResponse"]["enabledCardCount"] == 3


def test_no_exempt_card_is_zero():
    assert value("antiPassbackExemptCardCount", body([person(1, [card(1), card(2)])])) == 0


def test_flipping_the_exemption_changes_the_count():
    assert value("antiPassbackExemptCardCount", body([person(1, [card(1, exempt=False)])])) == 0
    assert value("antiPassbackExemptCardCount", body([person(1, [card(1, exempt=True)])])) == 1


def test_a_string_true_is_not_a_reading_and_a_missing_field_hides_a_zero():
    c = card(1)
    c["AntiPassbackExempt"] = "true"
    assert not_evaluated("antiPassbackExemptCardCount", body([person(1, [c])]))
    assert not_evaluated("antiPassbackExemptCardCount", body([person(1, [card(1, with_exempt_field=False)])]))
    assert not_evaluated("antiPassbackExemptCardCount", body([person(1, [card(1, with_exempt_field=False), card(2, exempt=True)])]))


def test_camel_case_projection_is_read():
    people = [{"commonName": "P", "cardAssignments": [{"isDisabled": False, "expiresOn": when(-2), "antiPassbackExempt": True}]}]
    assert value("expiredButActiveCardCount", body(people)) == 1
    assert value("antiPassbackExemptCardCount", body(people)) == 1


@pytest.mark.parametrize("key", [EXPIRED[0], EXEMPT[0]])
def test_partial_read_is_not_scored_even_with_a_positive(key):
    people = [person(1, [card(1, when(-5), exempt=True)])]
    assert not_evaluated(key, body(people, truncated=True))


@pytest.mark.parametrize("key", [EXPIRED[0], EXEMPT[0]])
def test_empty_population_is_not_measured(key):
    assert not_evaluated(key, body([]))
    assert not_evaluated(key, body([person(1, [])]))
    assert not_evaluated(key, body([person(1, [card(1, disabled=True)])]))
    assert not_evaluated(key, body([{"CommonName": "no cards field"}]))


@pytest.mark.parametrize("key", [EXPIRED[0], EXEMPT[0]])
def test_bare_list_and_string_inputs_are_read(key):
    people = [person(1, [card(1, when(-5), exempt=True)])]
    assert value(key, people) == 1
    import json
    assert value(key, json.dumps({"people": people})) == 1


NO_EVIDENCE = [
    None, {}, [], "", "{}",
    {"errors": ["Unauthorized"]},
    {"error": "invalid_client", "status_code": 400},
    {"statusCode": 403, "error": "Forbidden"},
    {"data": {"apiResponse": {"Message": "denied", "error": True}}, "validation": {}},
    {"data": {"apiResponse": {"status_code": 500, "message": "boom"}}, "validation": {}},
    {"data": {"unrelated": 1}, "validation": {"status": "skipped", "errors": [], "warnings": []}},
    {"people": ["a", "b"]},
    {"people": [1, 2]},
]


@pytest.mark.parametrize("key", [EXPIRED[0], EXEMPT[0]])
@pytest.mark.parametrize("payload", NO_EVIDENCE)
def test_no_evidence_is_not_measured(key, payload):
    assert not_evaluated(key, payload)


@pytest.mark.parametrize("flag", ["true", "false", 1, 0, None])
def test_an_exempt_flag_that_is_not_a_boolean_is_not_a_reading(flag):
    """A string, a number or null is not the vendor's boolean: no count can be shown beside it."""
    people = [person(1, [card(1, exempt=False), dict(card(2), AntiPassbackExempt=flag)])]
    assert not_evaluated("antiPassbackExemptCardCount", body(people))
    flagged = [person(1, [card(1, exempt=True), dict(card(2), AntiPassbackExempt=flag)])]
    assert not_evaluated("antiPassbackExemptCardCount", body(flagged))
