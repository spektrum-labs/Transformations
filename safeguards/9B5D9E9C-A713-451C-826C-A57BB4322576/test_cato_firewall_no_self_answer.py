"""Cato firewall_transform: isFirewallLoggingEnabled is answered from the audit feed, never from a field of the body.

Two rules, both on the one key isFirewallLoggingEnabled.

1. The transform used to set it from a field of that name in the body it was judging. Cato's API sends no such field, so
   a body (or a stored replay, or a hostile response) that carried one chose its own answer. The field is never read.
2. The criterion is answered only by an audit feed that was actually read. A feed that is absent, null, empty, not an
   object, or has a fetchedCount that is missing or cannot be read as a count was not measured, so the answer is None
   with a data-collection error (Not evaluated), never False. Only a feed that was read with fetchedCount 0 is the
   measured False; a fetchedCount above zero is True. The same holds on the validation-failed and exception paths.
Synthetic data only."""
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = os.path.join(HERE, "firewall_transform.py")
KEY = "isFirewallLoggingEnabled"

FIREWALL = {"data": {"policy": {"internetFirewall": {"policy": {
    "enabled": True, "rules": [{"rule": {"name": "block-all-inbound"}}]}}}}}


def load():
    spec = importlib.util.spec_from_file_location("cato_firewall_no_self_answer", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


@pytest.fixture(scope="module")
def tx():
    return load()


def logging_value(out):
    return out["transformedResponse"][KEY]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def reasons(out):
    evaluation = out["additionalInfo"]["evaluation"]
    return " ".join(evaluation["passReasons"] + evaluation["failReasons"])


def shapes(body):
    yield body
    yield json.dumps(body)
    yield {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}


def assert_not_evaluated(out):
    assert logging_value(out) is None
    assert collection(out)["status"] == "error"
    assert collection(out)["errors"]
    assert "Firewall logging" not in reasons(out)


def assert_measured(out, value):
    assert logging_value(out) is value
    assert collection(out)["status"] == "success"
    assert collection(out)["errors"] == []


SELF_ANSWER_BODIES = [
    ("the field alone, true", {KEY: True}),
    ("the field as text", {KEY: "true"}),
    ("the field as a number", {KEY: 1}),
    ("the field inside a result wrapper", {"result": {KEY: True}}),
    ("the field inside a response wrapper", {"response": {KEY: True}}),
    ("the field beside firewall data", {KEY: True, "firewall": FIREWALL}),
    ("the field beside an audit feed with no count", {KEY: True, "auditFeed": {}}),
    ("the field beside an audit feed that is not an object", {KEY: True, "auditFeed": "later"}),
]


@pytest.mark.parametrize("name,body", SELF_ANSWER_BODIES, ids=[c[0] for c in SELF_ANSWER_BODIES])
def test_a_field_named_like_the_criterion_never_answers_it(tx, name, body):
    for shape in shapes(body):
        assert_not_evaluated(tx(shape))


def test_the_field_does_not_override_a_measured_empty_feed(tx):
    body = {KEY: True, "auditFeed": {"fetchedCount": 0}}
    for shape in shapes(body):
        assert_measured(tx(shape), False)


def test_the_field_does_not_override_a_fetched_feed(tx):
    body = {KEY: False, "auditFeed": {"fetchedCount": 3}}
    for shape in shapes(body):
        assert_measured(tx(shape), True)


FETCHED = [("one", 1), ("five", 5), ("text", "7"), ("text with spaces", " 12 "), ("a whole float", 3.0)]


@pytest.mark.parametrize("name,count", FETCHED, ids=[c[0] for c in FETCHED])
def test_a_feed_that_was_read_with_entries_answers_true(tx, name, count):
    for shape in shapes({"auditFeed": {"fetchedCount": count}}):
        out = tx(shape)
        assert_measured(out, True)
        assert "Firewall logging is enabled" in reasons(out)


EMPTY = [("zero", 0), ("text zero", "0"), ("text zero with spaces", " 0 "), ("float zero", 0.0)]


@pytest.mark.parametrize("name,count", EMPTY, ids=[c[0] for c in EMPTY])
def test_only_a_feed_that_was_read_with_zero_entries_is_the_measured_false(tx, name, count):
    for shape in shapes({"auditFeed": {"fetchedCount": count}}):
        out = tx(shape)
        assert_measured(out, False)
        assert "Firewall logging is not enabled" in reasons(out)


def test_a_feed_given_as_text_is_read(tx):
    assert_measured(tx({"auditFeed": json.dumps({"fetchedCount": 4})}), True)
    assert_measured(tx({"auditFeed": json.dumps({"fetchedCount": 0})}), False)
    assert_measured(tx({"auditFeed": str({"fetchedCount": 4})}), True)


NO_FEED_BODIES = [
    ("an empty body", {}),
    ("firewall data and no feed", {"firewall": FIREWALL}),
    ("a body with other keys", {"something": 1}),
    ("a feed that is null", {"auditFeed": None}),
    ("a feed that is empty text", {"auditFeed": ""}),
    ("a feed that is text that is not an object", {"auditFeed": "later"}),
    ("a feed that is text for a list", {"auditFeed": "[1, 2]"}),
    ("a feed that is a number", {"auditFeed": 5}),
    ("a feed that is true", {"auditFeed": True}),
    ("a feed that is false", {"auditFeed": False}),
    ("a feed that is a list", {"auditFeed": [{"fetchedCount": 5}]}),
    ("a feed that is an empty list", {"auditFeed": []}),
]


@pytest.mark.parametrize("name,body", NO_FEED_BODIES, ids=[c[0] for c in NO_FEED_BODIES])
def test_a_feed_that_is_absent_or_not_an_object_is_not_evaluated(tx, name, body):
    for shape in shapes(body):
        assert_not_evaluated(tx(shape))


BAD_COUNT_BODIES = [
    ("no count", {"auditFeed": {}}),
    ("a different key", {"auditFeed": {"count": 5}}),
    ("count null", {"auditFeed": {"fetchedCount": None}}),
    ("count empty text", {"auditFeed": {"fetchedCount": ""}}),
    ("count blank text", {"auditFeed": {"fetchedCount": "  "}}),
    ("count text that is not a number", {"auditFeed": {"fetchedCount": "many"}}),
    ("count text with a sign", {"auditFeed": {"fetchedCount": "-1"}}),
    ("count a negative number", {"auditFeed": {"fetchedCount": -1}}),
    ("count a fraction", {"auditFeed": {"fetchedCount": 2.5}}),
    ("count not a number float", {"auditFeed": {"fetchedCount": float("nan")}}),
    ("count infinite", {"auditFeed": {"fetchedCount": float("inf")}}),
    ("count true", {"auditFeed": {"fetchedCount": True}}),
    ("count false", {"auditFeed": {"fetchedCount": False}}),
    ("count a list", {"auditFeed": {"fetchedCount": [5]}}),
    ("count an object", {"auditFeed": {"fetchedCount": {"n": 5}}}),
]


@pytest.mark.parametrize("name,body", BAD_COUNT_BODIES, ids=[c[0] for c in BAD_COUNT_BODIES])
def test_a_feed_with_no_readable_count_is_not_evaluated(tx, name, body):
    shapes_to_try = [body]
    if "nan" not in name and "infinite" not in name:  # json.dumps would turn these into non-JSON text
        shapes_to_try = list(shapes(body))
    for shape in shapes_to_try:
        assert_not_evaluated(tx(shape))


def test_the_other_answers_are_unchanged_when_the_feed_was_not_read(tx):
    body = {"firewall": FIREWALL}
    out = tx(body)
    assert_not_evaluated(out)
    assert out["transformedResponse"]["internetFirewallRules"] == ["block-all-inbound"]
    assert out["transformedResponse"]["isFirewallConfigured"] is True
    assert out["transformedResponse"]["isFirewallEnabled"] is False


def test_the_other_answers_are_unchanged_when_the_feed_was_read(tx):
    body = {"firewall": FIREWALL, "auditFeed": {"fetchedCount": 2}}
    out = tx(body)
    assert_measured(out, True)
    assert out["transformedResponse"]["internetFirewallRules"] == ["block-all-inbound"]
    assert out["transformedResponse"]["isFirewallConfigured"] is True


def test_a_failed_validation_is_not_evaluated(tx):
    body = {"data": {"auditFeed": {"fetchedCount": 9}},
            "validation": {"status": "failed", "errors": ["bad input"], "warnings": []}}
    assert_not_evaluated(tx(body))


def test_an_exception_is_not_evaluated(tx):
    for bad in ("not json", {"firewall": [1, 2]}, {"firewall": "also not json"}, {"wanNetwork": 7}):
        out = tx(bad)
        assert logging_value(out) is None
        assert collection(out)["status"] == "error"
        assert collection(out)["errors"]


def test_an_input_that_is_not_a_body_is_not_evaluated(tx):
    for bad in (None, 5, [], b"not json"):
        out = tx(bad)
        assert logging_value(out) is None
        assert collection(out)["status"] == "error"
        assert collection(out)["errors"]


def test_the_error_text_is_fixed_and_carries_no_vendor_text(tx):
    marker = "vendor-supplied-marker-text"
    out = tx({"auditFeed": {"fetchedCount": marker}})
    assert logging_value(out) is None
    assert marker not in " ".join(collection(out)["errors"])
