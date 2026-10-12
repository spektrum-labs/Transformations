"""Cato firewall_transform: nothing is answered from a field of the body, and nothing that was not read answers False.

Rules, all on the Cato firewall answers (isFirewallLoggingEnabled, isFirewallEnabled, isFirewallConfigured).

1. isFirewallLoggingEnabled used to be set from a field of that name in the body it was judging. Cato's API sends no such
   field, so a body (or a stored replay, or a hostile response) that carried one chose its own answer. It is never read.
2. isFirewallLoggingEnabled is answered only by an audit feed that was actually read. A feed that is absent, null, empty,
   not an object, or has a fetchedCount that is missing or cannot be read as a count was not measured: None with a
   data-collection error (Not evaluated), never False. Only a feed read with fetchedCount 0 is the measured False.
3. isFirewallEnabled and isFirewallConfigured are answered from the two policy layers (internet firewall, WAN network).
   A layer is read only when its policy object is there and its enabled flag is a boolean or the text "true"/"false"
   (any case, any spacing). Any other enabled value (a number, "maybe", "yes", null, a list) leaves the layer unread; an
   unread layer contributes no rules. When neither layer was read both answers are None with a data-collection error.
4. A failed validation and an exception give None for all three keys with a data-collection error whose text does not
   claim anything about the audit feed; the exception text taken from the failure is capped at 200 characters.
Synthetic data only."""
import importlib.util
import json
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
FILE = os.path.join(HERE, "firewall_transform.py")
KEY = "isFirewallLoggingEnabled"
ENABLED = "isFirewallEnabled"
CONFIGURED = "isFirewallConfigured"
ALL_KEYS = (ENABLED, KEY, CONFIGURED)


def internet(enabled=True, names=("block-all-inbound",)):
    return {"data": {"policy": {"internetFirewall": {"policy": {
        "enabled": enabled, "rules": [{"rule": {"name": n}} for n in names]}}}}}


def wan(enabled=True, names=("allow-branch-traffic",)):
    return {"data": {"policy": {"wanNetwork": {"policy": {
        "enabled": enabled, "rules": [{"rule": {"name": n}} for n in names]}}}}}


FIREWALL = internet()


def full(**extra):
    """Both layers read, enabled, with rules. Extra keys (auditFeed and so on) go beside them."""
    out = {"firewall": internet(), "wanNetwork": wan()}
    out.update(extra)
    return out


def load():
    spec = importlib.util.spec_from_file_location("cato_firewall_no_self_answer", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


@pytest.fixture(scope="module")
def tx():
    return load()


def value(out, key=KEY):
    return out["transformedResponse"][key]


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def reasons(out):
    evaluation = out["additionalInfo"]["evaluation"]
    return " ".join(evaluation["passReasons"] + evaluation["failReasons"])


def shapes(body):
    yield body
    yield json.dumps(body)
    yield {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}


def assert_logging_not_evaluated(out):
    assert value(out) is None
    assert collection(out)["status"] == "error"
    assert collection(out)["errors"]
    assert "Firewall logging" not in reasons(out)


def assert_measured(out, want):
    """Logging is the measured want and nothing was left unread."""
    assert value(out) is want
    assert collection(out)["status"] == "success", collection(out)
    assert collection(out)["errors"] == []


def assert_nothing_evaluated(out):
    for key in ALL_KEYS:
        assert value(out, key) is None, key
    assert collection(out)["status"] == "error"
    assert collection(out)["errors"]


# ------------------------------------------------------------------ rule 1: a field of the body never answers

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
        assert_logging_not_evaluated(tx(shape))


def test_the_field_does_not_override_a_measured_empty_feed(tx):
    body = full(**{KEY: True, "auditFeed": {"fetchedCount": 0}})
    for shape in shapes(body):
        assert_measured(tx(shape), False)


def test_the_field_does_not_override_a_fetched_feed(tx):
    body = full(**{KEY: False, "auditFeed": {"fetchedCount": 3}})
    for shape in shapes(body):
        assert_measured(tx(shape), True)


# ------------------------------------------------------------------ rule 2: the audit feed

FETCHED = [("one", 1), ("five", 5), ("text", "7"), ("text with spaces", " 12 "), ("a whole float", 3.0)]


@pytest.mark.parametrize("name,count", FETCHED, ids=[c[0] for c in FETCHED])
def test_a_feed_that_was_read_with_entries_answers_true(tx, name, count):
    for shape in shapes(full(auditFeed={"fetchedCount": count})):
        out = tx(shape)
        assert_measured(out, True)
        assert "Firewall logging is enabled" in reasons(out)


EMPTY = [("zero", 0), ("text zero", "0"), ("text zero with spaces", " 0 "), ("float zero", 0.0)]


@pytest.mark.parametrize("name,count", EMPTY, ids=[c[0] for c in EMPTY])
def test_only_a_feed_that_was_read_with_zero_entries_is_the_measured_false(tx, name, count):
    for shape in shapes(full(auditFeed={"fetchedCount": count})):
        out = tx(shape)
        assert_measured(out, False)
        assert "Firewall logging is not enabled" in reasons(out)


def test_a_feed_given_as_text_is_read(tx):
    assert_measured(tx(full(auditFeed=json.dumps({"fetchedCount": 4}))), True)
    assert_measured(tx(full(auditFeed=json.dumps({"fetchedCount": 0}))), False)
    assert_measured(tx(full(auditFeed=str({"fetchedCount": 4}))), True)


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
        assert_logging_not_evaluated(tx(shape))
    for shape in shapes(full(**body)):
        assert_logging_not_evaluated(tx(shape))


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
    for source in (body, full(**body)):
        shapes_to_try = [source]
        if "nan" not in name and "infinite" not in name:  # json.dumps would turn these into non-JSON text
            shapes_to_try = list(shapes(source))
        for shape in shapes_to_try:
            assert_logging_not_evaluated(tx(shape))


def test_a_feed_not_read_leaves_the_layer_answers_as_they_were(tx):
    out = tx(full())
    assert_logging_not_evaluated(out)
    assert value(out, ENABLED) is True
    assert value(out, CONFIGURED) is True
    assert out["transformedResponse"]["internetFirewallRules"] == ["block-all-inbound"]
    assert out["transformedResponse"]["wanNetworkRules"] == ["allow-branch-traffic"]


def test_the_layer_answers_are_unchanged_when_everything_was_read(tx):
    out = tx(full(auditFeed={"fetchedCount": 2}))
    assert_measured(out, True)
    assert value(out, ENABLED) is True
    assert value(out, CONFIGURED) is True


def test_the_error_text_is_fixed_and_carries_no_vendor_text(tx):
    marker = "vendor-supplied-marker-text"
    out = tx(full(auditFeed={"fetchedCount": marker}))
    assert value(out) is None
    assert marker not in " ".join(collection(out)["errors"])


# ------------------------------------------------------------------ rule 3: the policy layers

def feed(**extra):
    out = {"auditFeed": {"fetchedCount": 2}}
    out.update(extra)
    return out


READ_LAYERS = [
    ("both enabled with rules", {"firewall": internet(True), "wanNetwork": wan(True)}, True, True),
    ("both enabled, no rules", {"firewall": internet(True, ()), "wanNetwork": wan(True, ())}, True, False),
    ("internet disabled", {"firewall": internet(False), "wanNetwork": wan(True)}, False, True),
    ("wan disabled", {"firewall": internet(True), "wanNetwork": wan(False)}, False, True),
    ("both disabled, no rules", {"firewall": internet(False, ()), "wanNetwork": wan(False, ())}, False, False),
    ("only the internet layer, enabled", {"firewall": internet(True)}, False, True),
    ("only the wan layer, enabled", {"wanNetwork": wan(True)}, False, True),
    ("only the internet layer, disabled with no rules", {"firewall": internet(False, ())}, False, False),
    ("internet enabled as text", {"firewall": internet("true"), "wanNetwork": wan("TRUE")}, True, True),
    ("internet enabled as text with spaces", {"firewall": internet(" True "), "wanNetwork": wan(" true")}, True, True),
    ("internet disabled as text", {"firewall": internet("false"), "wanNetwork": wan(True)}, False, True),
    ("both disabled as text", {"firewall": internet(" FALSE "), "wanNetwork": wan("False")}, False, True),
]


@pytest.mark.parametrize("name,layers,enabled,configured", READ_LAYERS, ids=[c[0] for c in READ_LAYERS])
def test_a_layer_that_was_read_answers_as_it_always_did(tx, name, layers, enabled, configured):
    for shape in shapes(dict(layers, **feed())):
        out = tx(shape)
        assert_measured(out, True)
        assert value(out, ENABLED) is enabled
        assert value(out, CONFIGURED) is configured


UNREADABLE_FLAGS = [("maybe", "maybe"), ("yes", "yes"), ("no", "no"), ("on", "on"), ("off", "off"),
                    ("text one", "1"), ("text zero", "0"), ("number one", 1), ("number zero", 0),
                    ("number two", 2), ("a fraction", 1.5), ("null", None), ("empty text", ""),
                    ("text null", "None"), ("a list", ["true"]), ("an empty list", []), ("an object", {"x": 1})]


@pytest.mark.parametrize("name,flag", UNREADABLE_FLAGS, ids=[c[0] for c in UNREADABLE_FLAGS])
def test_an_enabled_flag_that_is_not_a_boolean_leaves_both_layers_unread(tx, name, flag):
    body = dict({"firewall": internet(flag), "wanNetwork": wan(flag)}, **feed())
    for shape in shapes(body):
        out = tx(shape)
        assert value(out, ENABLED) is None
        assert value(out, CONFIGURED) is None
        assert value(out, KEY) is True  # the feed was read, so logging is still measured
        assert collection(out)["status"] == "error"
        assert collection(out)["errors"]
        assert out["transformedResponse"]["internetFirewallRules"] == []
        assert out["transformedResponse"]["wanNetworkRules"] == []


@pytest.mark.parametrize("name,flag", UNREADABLE_FLAGS, ids=[c[0] for c in UNREADABLE_FLAGS])
def test_an_unreadable_flag_is_never_read_as_enabled(tx, name, flag):
    # The old reader took any truthy value ("false", "maybe", 2) as True. One layer unreadable, the other enabled:
    # the unreadable layer adds nothing and the firewall is not reported enabled.
    for body in (dict({"firewall": internet(flag), "wanNetwork": wan(True)}, **feed()),
                 dict({"firewall": internet(True), "wanNetwork": wan(flag)}, **feed())):
        for shape in shapes(body):
            out = tx(shape)
            assert value(out, ENABLED) is not True
            assert value(out, ENABLED) is not None  # the other layer was read
            assert len(out["transformedResponse"]["internetFirewallRules"]
                       + out["transformedResponse"]["wanNetworkRules"]) == 1


def test_the_text_false_is_a_disabled_layer_not_an_enabled_one(tx):
    out = tx(dict({"firewall": internet("false", ()), "wanNetwork": wan("false", ())}, **feed()))
    assert value(out, ENABLED) is False
    assert value(out, CONFIGURED) is False
    assert collection(out)["status"] == "success"


def test_a_layer_with_no_enabled_key_is_unread(tx):
    policy_only = {"data": {"policy": {"internetFirewall": {"policy": {"rules": [{"rule": {"name": "r"}}]}}}}}
    out = tx(dict({"firewall": policy_only}, **feed()))
    assert value(out, ENABLED) is None
    assert value(out, CONFIGURED) is None
    assert out["transformedResponse"]["internetFirewallRules"] == []


NO_LAYER_BODIES = [
    ("an empty body", {}),
    ("another key only", {"something": 1}),
    ("a feed and no layer", {"auditFeed": {"fetchedCount": 3}}),
    ("a firewall key with no data", {"firewall": {}}),
    ("a firewall key with data and no policy", {"firewall": {"data": {}}}),
    ("a policy with no internet firewall", {"firewall": {"data": {"policy": {}}}}),
    ("an internet firewall with no policy", {"firewall": {"data": {"policy": {"internetFirewall": {}}}}}),
    ("a wan layer with no policy", {"wanNetwork": {"data": {"policy": {"wanNetwork": {}}}}}),
]


@pytest.mark.parametrize("name,body", NO_LAYER_BODIES, ids=[c[0] for c in NO_LAYER_BODIES])
def test_a_body_with_no_layer_read_answers_none_for_enabled_and_configured(tx, name, body):
    for shape in shapes(body):
        out = tx(shape)
        assert value(out, ENABLED) is None
        assert value(out, CONFIGURED) is None
        assert collection(out)["status"] == "error"
        assert collection(out)["errors"]
        assert out["transformedResponse"]["internetFirewallRules"] == []
        assert out["transformedResponse"]["wanNetworkRules"] == []


def test_a_body_with_no_layer_still_measures_a_feed_that_was_read(tx):
    out = tx({"auditFeed": {"fetchedCount": 3}})
    assert value(out) is True
    assert value(out, ENABLED) is None
    out = tx({"auditFeed": {"fetchedCount": 0}})
    assert value(out) is False
    assert value(out, CONFIGURED) is None


NON_DICT_DATA = [("a list", [1, 2]), ("text", "not a body"), ("null", None), ("a number", 7), ("true", True)]


@pytest.mark.parametrize("name,data", NON_DICT_DATA, ids=[c[0] for c in NON_DICT_DATA])
def test_data_that_is_not_an_object_answers_none_for_every_key(tx, name, data):
    out = tx({"data": data, "validation": {"status": "passed", "errors": [], "warnings": []}})
    assert_nothing_evaluated(out)


def test_not_evaluated_findings_do_not_claim_a_fail(tx):
    out = tx({})
    for finding in out["additionalInfo"]["evaluation"]["additionalFindings"]:
        assert finding["status"] != "fail"
    assert "Firewall logging" not in reasons(out)


# ------------------------------------------------------------------ rule 4: validation failed and exceptions

VALIDATION_FAILED = {"data": full(auditFeed={"fetchedCount": 9}),
                     "validation": {"status": "failed", "errors": ["bad input"], "warnings": []}}


def test_a_failed_validation_answers_none_for_every_key(tx):
    out = tx(VALIDATION_FAILED)
    assert_nothing_evaluated(out)
    assert "Audit feed" not in " ".join(collection(out)["errors"])
    assert "alidation" in " ".join(collection(out)["errors"])


class Boom(dict):
    """A body whose every read raises with a long message."""

    def __contains__(self, key):
        raise RuntimeError("x" * 500)


def test_an_exception_answers_none_for_every_key(tx):
    for bad in ("not json", {"firewall": [1, 2]}, {"firewall": "also not json"}, {"wanNetwork": 7},
                {"firewall": {"data": {"policy": {"internetFirewall": {"policy": {"enabled": True, "rules": 5}}}}}}):
        out = tx(bad)
        assert_nothing_evaluated(out)
        assert "Audit feed" not in " ".join(collection(out)["errors"])


def test_an_input_that_is_not_a_body_answers_none_for_every_key(tx):
    for bad in (None, 5, [], b"not json"):
        out = tx(bad)
        assert_nothing_evaluated(out)
        assert "Audit feed" not in " ".join(collection(out)["errors"])


def test_the_exception_text_from_the_failure_is_capped_at_200_characters(tx):
    out = tx(Boom())
    assert_nothing_evaluated(out)
    transformation = out["additionalInfo"]["transformation"]["errors"]
    assert transformation and transformation[0] == "x" * 200
    assert "x" * 201 not in json.dumps(out)
    assert "Audit feed" not in " ".join(collection(out)["errors"])
