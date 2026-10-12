"""Cloudflare firewall_transform: a stringified flag reads like the boolean it spells, an unreadable flag is not an
active rule, and a further page of rules is a partial read.

Cloudflare sends paused and enabled as booleans, but a stored replay can carry them as text. The text "true" in paused,
or "false" in enabled, used to read as an enforcing rule (`paused is True` is False for a string), so a paused rule
returned True. A flag that is neither boolean nor a stringified boolean (a number, "maybe", a list) says nothing about
the rule: a rule that could enforce and whose state is unreadable is not counted as active, and when nothing else shows
an enforcing rule the answer is None, never False. The paging markers (result_info total_pages, page and cursors, or a
paging block with pages or next) mean more rules exist than were read, so a "no enforcing rule" False reads None; an
enforcing rule that was read still proves True. Synthetic data only."""
import copy
import importlib.util
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
FILE = os.path.join(HERE, "firewall_transform.py")
KEY = "isFirewallEnabled"


def load_plain():
    spec = importlib.util.spec_from_file_location("cloudflare_flags_and_paging", FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.transform


def load_sandboxed():
    pytest.importorskip("RestrictedPython")
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import restricted_sandbox
    with open(FILE) as fh:
        return restricted_sandbox.load(fh.read())["transform"]


@pytest.fixture(params=["plain", "sandboxed"])
def tx(request):
    return load_plain() if request.param == "plain" else load_sandboxed()


def rule(rule_id="a", **changes):
    out = {"id": rule_id, "action": "block", "description": "rule " + rule_id,
           "filter": {"id": "f-" + rule_id, "expression": "ip.src eq 192.0.2.1", "paused": False},
           "paused": False, "priority": 50, "products": ["waf"], "ref": "R-" + rule_id}
    out.update(changes)
    return out


def with_filter_paused(value, rule_id="a"):
    out = rule(rule_id)
    out["filter"]["paused"] = value
    return out


def legacy(rules, **info):
    result_info = {"count": len(rules), "page": 1, "per_page": 20, "total_count": len(rules)}
    result_info.update(info)
    return {"errors": [], "messages": [], "success": True, "result": rules, "result_info": result_info}


def part(body):
    result = body.get("result") if isinstance(body, dict) else None
    return {"rules": result if isinstance(result, list) else [], "apiResponse": body}


def ruleset(rules):
    return {"errors": [], "messages": [], "success": True,
            "result": {"id": "2f2feab2026849078ba485f918791bdc", "kind": "zone", "name": "default",
                       "phase": "http_request_firewall_custom", "rules": rules}}


def rs_rule(action="block", rule_id="r1", **changes):
    out = {"id": rule_id, "version": "1", "action": action, "expression": "ip.src.asnum eq 64496"}
    out.update(changes)
    return out


def shapes(body):
    yield body
    yield json.dumps(body)
    yield {"data": body, "validation": {"status": "passed", "errors": [], "warnings": []}}


def collection(out):
    return out["additionalInfo"]["dataCollection"]


def assert_measured(out, want):
    assert collection(out)["status"] == "success", collection(out)
    assert out["transformedResponse"][KEY] is want


def assert_not_evaluated(out):
    assert collection(out)["status"] == "error"
    assert collection(out)["errors"]
    assert out["transformedResponse"][KEY] is None


# --------------------------------------------------------------------- stringified flags

PAUSED_TEXT = ["true", "True", "TRUE", " true ", "\ttrue\n"]
NOT_PAUSED_TEXT = ["false", "False", "FALSE", " false "]
ABSENT = [None, "", "  ", "None", "null", "NULL"]
UNREADABLE = ["maybe", "yes", "no", "on", "off", "ON", "enabled", "1", "0", 1, 0, 2, 1.5, ["true"], [], {"paused": True}, {}]


@pytest.mark.parametrize("value", PAUSED_TEXT)
def test_a_rule_paused_as_text_is_not_active(tx, value):
    for shape in shapes(part(legacy([rule(paused=value)]))):
        assert_measured(tx(shape), False)


@pytest.mark.parametrize("value", PAUSED_TEXT)
def test_a_rule_whose_filter_is_paused_as_text_is_not_active(tx, value):
    for shape in shapes(part(legacy([with_filter_paused(value)]))):
        assert_measured(tx(shape), False)


@pytest.mark.parametrize("value", NOT_PAUSED_TEXT)
def test_a_rule_not_paused_as_text_is_active(tx, value):
    for shape in shapes(part(legacy([rule(paused=value)]))):
        assert_measured(tx(shape), True)
    for shape in shapes(part(legacy([with_filter_paused(value)]))):
        assert_measured(tx(shape), True)


@pytest.mark.parametrize("value", ABSENT)
def test_an_absent_paused_flag_is_an_active_rule(tx, value):
    for shape in shapes(part(legacy([rule(paused=value)]))):
        assert_measured(tx(shape), True)


@pytest.mark.parametrize("value", ["false", "False", " FALSE "])
def test_a_ruleset_rule_disabled_as_text_is_not_active(tx, value):
    for shape in shapes({"rules": [], "apiResponse": ruleset([rs_rule(enabled=value)])}):
        assert_measured(tx(shape), False)


@pytest.mark.parametrize("value", ["true", "True", " TRUE "])
def test_a_ruleset_rule_enabled_as_text_is_active(tx, value):
    for shape in shapes({"rules": [], "apiResponse": ruleset([rs_rule(enabled=value)])}):
        assert_measured(tx(shape), True)


@pytest.mark.parametrize("value", ABSENT)
def test_an_absent_enabled_flag_is_an_enabled_rule(tx, value):
    for shape in shapes({"rules": [], "apiResponse": ruleset([rs_rule(enabled=value)])}):
        assert_measured(tx(shape), True)


def test_the_booleans_still_read_as_before(tx):
    assert_measured(tx(part(legacy([rule(paused=True)]))), False)
    assert_measured(tx(part(legacy([rule(paused=False)]))), True)
    assert_measured(tx({"rules": [], "apiResponse": ruleset([rs_rule(enabled=False)])}), False)
    assert_measured(tx({"rules": [], "apiResponse": ruleset([rs_rule(enabled=True)])}), True)


# --------------------------------------------------------------------- unreadable flags

@pytest.mark.parametrize("value", UNREADABLE, ids=[repr(v) for v in UNREADABLE])
def test_an_unreadable_paused_flag_on_the_only_enforcing_rule_is_not_evaluated(tx, value):
    for shape in shapes(part(legacy([rule(paused=value)]))):
        assert_not_evaluated(tx(shape))


@pytest.mark.parametrize("value", UNREADABLE, ids=[repr(v) for v in UNREADABLE])
def test_an_unreadable_filter_paused_flag_is_not_evaluated(tx, value):
    for shape in shapes(part(legacy([with_filter_paused(value)]))):
        assert_not_evaluated(tx(shape))


@pytest.mark.parametrize("value", UNREADABLE, ids=[repr(v) for v in UNREADABLE])
def test_an_unreadable_enabled_flag_is_not_evaluated(tx, value):
    for shape in shapes({"rules": [], "apiResponse": ruleset([rs_rule(enabled=value)])}):
        assert_not_evaluated(tx(shape))


def test_an_enforcing_rule_that_was_read_still_proves_true_beside_an_unreadable_one(tx):
    body = part(legacy([rule("a", paused="maybe"), rule("b")]))
    for shape in shapes(body):
        assert_measured(tx(shape), True)


def test_a_paused_rule_beside_an_unreadable_one_is_not_evaluated(tx):
    body = part(legacy([rule("a", paused="maybe"), rule("b", paused="true")]))
    for shape in shapes(body):
        assert_not_evaluated(tx(shape))


def test_an_unreadable_rule_beside_a_non_enforcing_one_is_not_evaluated(tx):
    body = part(legacy([rule("a", paused=1), rule("b", action="allow")]))
    for shape in shapes(body):
        assert_not_evaluated(tx(shape))


@pytest.mark.parametrize("action", ["allow", "log", "bypass", "skip", ""])
def test_an_unreadable_flag_on_a_rule_that_could_not_enforce_does_not_matter(tx, action):
    body = part(legacy([rule("a", paused="maybe", action=action)]))
    for shape in shapes(body):
        assert_measured(tx(shape), False)


def test_a_known_inactive_flag_wins_over_an_unreadable_one(tx):
    # Paused text "true" on the rule, an unreadable filter flag: the rule is paused whatever the filter says.
    both = rule("a", paused="true")
    both["filter"]["paused"] = "maybe"
    for shape in shapes(part(legacy([both]))):
        assert_measured(tx(shape), False)
    # Enabled false on a ruleset rule, an unreadable paused flag beside it.
    for shape in shapes({"rules": [], "apiResponse": ruleset([rs_rule(enabled="false", paused="maybe")])}):
        assert_measured(tx(shape), False)


def test_every_rule_paused_in_text_is_a_measured_false_with_the_reason_naming_them(tx):
    out = tx(part(legacy([rule("a", paused="true"), rule("b", paused="TRUE")])))
    assert_measured(out, False)
    assert "rule a" in " ".join(out["additionalInfo"]["evaluation"]["failReasons"])


# --------------------------------------------------------------------- paging

def only_allow(**info):
    return part(legacy([rule("a", action="allow")], **info))


def paged(paging, **info):
    """The same body with a paging block beside the result, inside the Cloudflare body."""
    body = legacy([rule("a", action="allow")], **info)
    body["paging"] = paging
    return part(body)


COMPLETE = [
    ("no result_info paging marker", only_allow()),
    ("one page of one", only_allow(total_pages=1)),
    ("one page of one, text", only_allow(total_pages="1")),
    ("pages above one but the total equals the rules read", only_allow(total_pages=3)),
    ("cursors after null", only_allow(cursors={"after": None})),
    ("cursors after empty", only_allow(cursors={"after": ""})),
    ("cursors after stringified null", only_allow(cursors={"after": "None"})),
    ("cursor stringified null", only_allow(cursor="null")),
    ("empty paging block", paged({})),
    ("paging next empty list", paged({"next": []})),
    ("paging next null", paged({"next": None})),
    ("paging next empty text", paged({"next": ""})),
    ("paging pages one", paged({"pages": 1})),
    ("paging pages above one but the total equals the rules read", paged({"pages": 4})),
    ("paging pages null", paged({"pages": None})),
]

PARTIAL = [
    ("more pages and no total", part({"success": True, "errors": [], "messages": [],
                                       "result": [rule("a", action="allow")],
                                       "result_info": {"count": 1, "page": 1, "per_page": 1, "total_pages": 3}})),
    ("more pages, text, and no total", part({"success": True, "errors": [], "messages": [],
                                              "result": [rule("a", action="allow")],
                                              "result_info": {"page": 1, "total_pages": "2"}})),
    ("more pages and a total the rules do not reach", only_allow(total_pages=3, total_count=60)),
    ("a page that does not start at the beginning", part({"success": True, "errors": [], "messages": [],
                                                           "result": [rule("a", action="allow")],
                                                           "result_info": {"page": 2, "per_page": 1}})),
    ("a page number that is text above one", part({"success": True, "errors": [], "messages": [],
                                                    "result": [rule("a", action="allow")],
                                                    "result_info": {"page": "3"}})),
    ("a page total that cannot be read", part({"success": True, "errors": [], "messages": [],
                                                "result": [rule("a", action="allow")],
                                                "result_info": {"total_pages": "many"}})),
    ("a cursor after", only_allow(cursors={"after": "abc123"})),
    ("a cursor", only_allow(cursor="abc123")),
    ("paging pages above one", paged({"pages": 2}, total_count=None)),
    ("paging pages text above one", paged({"pages": "4"}, total_count=None)),
    ("paging pages that cannot be read", paged({"pages": "many"})),
    ("paging next as a list", paged({"next": ["https://api.example.invalid/next"]})),
    ("paging next as text", paged({"next": "https://api.example.invalid/next"})),
]


@pytest.mark.parametrize("name,body", COMPLETE, ids=[c[0] for c in COMPLETE])
def test_a_complete_read_keeps_its_false(tx, name, body):
    for shape in shapes(body):
        assert_measured(tx(shape), False)


@pytest.mark.parametrize("name,body", PARTIAL, ids=[c[0] for c in PARTIAL])
def test_a_further_page_makes_a_no_enforcing_rule_false_not_evaluated(tx, name, body):
    for shape in shapes(body):
        assert_not_evaluated(tx(shape))


@pytest.mark.parametrize("name,body", PARTIAL, ids=[c[0] for c in PARTIAL])
def test_a_further_page_does_not_undo_an_enforcing_rule_that_was_read(tx, name, body):
    enforcing = copy.deepcopy(body)
    holder = enforcing["apiResponse"] if "apiResponse" in enforcing else enforcing
    holder["result"] = [rule("a")]
    enforcing["rules"] = holder["result"]
    for shape in shapes(enforcing):
        assert_measured(tx(shape), True)


def with_result_info(info, rules=None):
    """The legacy body with result_info replaced by something that is not an object."""
    body = legacy(rules if rules is not None else [rule("a", action="allow")])
    body["result_info"] = info
    return part(body)


RESULT_INFO_NOT_AN_OBJECT_PARTIAL = [("text", "page 1 of 2"), ("text for an object", "{'total_count': 1}"), ("a number", 2),
                                     ("true", True), ("an empty list", []), ("a non-empty list", [1])]
RESULT_INFO_NOT_AN_OBJECT_COMPLETE = [("null", None), ("empty text", ""), ("stringified null", "None"),
                                      ("text null", "null"), ("false", False)]


@pytest.mark.parametrize("name,info", RESULT_INFO_NOT_AN_OBJECT_PARTIAL,
                         ids=[c[0] for c in RESULT_INFO_NOT_AN_OBJECT_PARTIAL])
def test_a_result_info_that_is_present_but_not_an_object_is_partial(tx, name, info):
    for shape in shapes(with_result_info(info)):
        assert_not_evaluated(tx(shape))


@pytest.mark.parametrize("name,info", RESULT_INFO_NOT_AN_OBJECT_PARTIAL,
                         ids=[c[0] for c in RESULT_INFO_NOT_AN_OBJECT_PARTIAL])
def test_a_result_info_that_is_not_an_object_does_not_undo_an_enforcing_rule(tx, name, info):
    for shape in shapes(with_result_info(info, rules=[rule("a")])):
        assert_measured(tx(shape), True)


@pytest.mark.parametrize("name,info", RESULT_INFO_NOT_AN_OBJECT_COMPLETE,
                         ids=[c[0] for c in RESULT_INFO_NOT_AN_OBJECT_COMPLETE])
def test_an_absent_result_info_is_a_complete_read(tx, name, info):
    for shape in shapes(with_result_info(info)):
        assert_measured(tx(shape), False)


def test_a_body_with_no_result_info_key_is_a_complete_read(tx):
    body = legacy([rule("a", action="allow")])
    del body["result_info"]
    for shape in shapes(part(body)):
        assert_measured(tx(shape), False)


def test_a_further_page_of_paused_rules_is_not_evaluated(tx):
    body = part(legacy([rule("a", paused=True), rule("b", paused="true")], total_pages=2, total_count=40))
    for shape in shapes(body):
        assert_not_evaluated(tx(shape))


def test_a_further_page_on_the_ruleset_shape_is_not_evaluated(tx):
    body = ruleset([rs_rule("log")])
    body["result_info"] = {"page": 1, "total_pages": 2}
    for shape in shapes({"rules": [], "apiResponse": body}):
        assert_not_evaluated(tx(shape))


def test_the_vendor_example_with_a_partial_page_and_an_enforcing_rule_is_still_true(tx):
    body = part(legacy([rule("a")], total_count=2000, total_pages=100))
    for shape in shapes(body):
        assert_measured(tx(shape), True)
