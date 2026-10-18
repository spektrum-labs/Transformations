"""Aurora (Cylance) transforms against synthetic bodies shaped like the documented responses.

Shapes from the Arctic Wolf Aurora Endpoint Defense API docs (field names only; the vendor pages
publish no example bodies):
* Get devices extended (GET /devices/v2/extended): page_items[] of devices with agent_version, state,
  policy, products, background_detection, plus page_number, page_size, total_pages, total_number_of_items.
* Get device count (GET /devices/v2/products): rows of name, version, count.
Every id, name and version below is made up.
"""
import importlib.util
from pathlib import Path

import pytest

HERE = Path(__file__).parent

KEYS = [
    ("confirmedlicensepurchased", "confirmedLicensePurchased"),
    ("iseppdeployed", "isEPPDeployed"),
    ("isedrdeployed", "isEDRDeployed"),
    ("iseppconfigured", "isEPPConfigured"),
    ("isbehavioralmonitoringvalid", "isBehavioralMonitoringValid"),
]


def load(name):
    spec = importlib.util.spec_from_file_location("aw_" + name, HERE / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def dev(products=("protect",), policy="pol-1", bg=True, agent="1.0.0.0"):
    d = {"id": "d", "name": "host", "state": "Online",
         "products": [{"name": p, "version": "3.2", "status": "Online"} for p in products]}
    if agent is not None:
        d["agent_version"] = agent
    if policy:
        d["policy"] = {"id": policy, "name": "Default"}
    if bg is not None:
        d["background_detection"] = bg
    return d


def page(*items, total=None):
    return {"page_number": 1, "page_size": 200, "total_number_of_items": len(items) if total is None else total,
            "total_pages": 1, "page_items": list(items)}


def out(name, body):
    return load(name).transform(body)


def result(name, body, key):
    return out(name, body)["transformedResponse"][key]


def errors(name, body):
    return out(name, body)["additionalInfo"]["dataCollection"]["errors"]


EMPTY = [None, {}, [], "", "not json", {"error": "unauthorized"}, {"apiResponse": {}}]


@pytest.mark.parametrize("body", EMPTY)
@pytest.mark.parametrize("name,key", KEYS)
def test_bodies_that_prove_nothing_are_false(name, key, body):
    assert result(name, body, key) is False


@pytest.mark.parametrize("body", [None, {}, "", "not json", {"error": "unauthorized"}, {"apiResponse": {}}, 7])
@pytest.mark.parametrize("name", ["confirmedlicensepurchased", "iseppdeployed", "iseppconfigured"])
def test_unreadable_replies_are_data_collection_errors(name, body):
    # Not evaluated, never a measured False.
    assert errors(name, body)


# ---- confirmedLicensePurchased: GET /devices/v2/products

def test_license_true_when_a_product_has_devices():
    rows = [{"name": "protect", "version": "3.2", "count": 12}]
    assert result("confirmedlicensepurchased", rows, "confirmedLicensePurchased") is True
    assert result("confirmedlicensepurchased", {"apiResponse": rows}, "confirmedLicensePurchased") is True
    assert result("confirmedlicensepurchased", {"page_items": rows}, "confirmedLicensePurchased") is True
    enriched = {"data": rows, "validation": {"status": "passed"}}
    assert result("confirmedlicensepurchased", enriched, "confirmedLicensePurchased") is True


def test_license_false_when_no_product_has_devices_and_it_is_a_real_answer():
    zero = [{"name": "protect", "version": "3.2", "count": 0}]
    assert result("confirmedlicensepurchased", zero, "confirmedLicensePurchased") is False
    assert not errors("confirmedlicensepurchased", zero)
    assert not errors("confirmedlicensepurchased", [])  # authenticated, nothing in use


@pytest.mark.parametrize("count", [None, "12", True, 1.5])
def test_license_rows_without_a_numeric_count_prove_nothing(count):
    rows = [{"name": "protect", "version": "3.2", "count": count}]
    assert result("confirmedlicensepurchased", rows, "confirmedLicensePurchased") is False
    assert errors("confirmedlicensepurchased", rows)


def test_license_ignores_rows_that_are_not_objects():
    rows = [None, "x", {"name": "protect", "version": "3.2", "count": 3}]
    assert result("confirmedlicensepurchased", rows, "confirmedLicensePurchased") is True


# ---- isEPPDeployed: agent_version on the extended device list

def test_epp_deployed_reads_agent_version():
    assert result("iseppdeployed", page(dev(agent="1.2.3.4")), "isEPPDeployed") is True
    assert result("iseppdeployed", page(dev(agent=""), dev(agent="1.2.3.4")), "isEPPDeployed") is True
    assert result("iseppdeployed", {"apiResponse": page(dev())}, "isEPPDeployed") is True


def test_epp_deployed_does_not_depend_on_product_names():
    # Product names are not published values; only the documented agent_version counts.
    assert result("iseppdeployed", page(dev(products=("optics",))), "isEPPDeployed") is True
    assert result("iseppdeployed", page(dev(products=("protect",), agent="")), "isEPPDeployed") is False


@pytest.mark.parametrize("version", ["", "  ", None, 5, {}])
def test_epp_deployed_false_when_the_field_is_present_but_empty(version):
    d = dev()
    d["agent_version"] = version
    body = page(d)
    assert result("iseppdeployed", body, "isEPPDeployed") is False
    assert not errors("iseppdeployed", body)


def test_epp_deployed_wrong_view_is_not_evaluated():
    body = page(dev(agent=None), dev(agent=None))
    assert result("iseppdeployed", body, "isEPPDeployed") is False
    assert errors("iseppdeployed", body)


def test_epp_deployed_empty_tenant_is_a_real_false():
    assert result("iseppdeployed", page(), "isEPPDeployed") is False
    assert not errors("iseppdeployed", page())


def test_epp_deployed_partial_read_still_proves_a_pass():
    assert result("iseppdeployed", page(dev(), total=900), "isEPPDeployed") is True


# ---- isEPPConfigured: policy on every device

def test_policy_assignment():
    assert result("iseppconfigured", page(dev(), dev()), "isEPPConfigured") is True
    assert result("iseppconfigured", page(dev(), dev(policy=None)), "isEPPConfigured") is False
    assert not errors("iseppconfigured", page(dev(), dev(policy=None)))


def test_policy_value_shape_is_not_assumed():
    string_policy = dev()
    string_policy["policy"] = "Default"
    assert result("iseppconfigured", page(string_policy, dev()), "isEPPConfigured") is True
    blank = dev()
    blank["policy"] = {}
    assert result("iseppconfigured", page(blank, dev()), "isEPPConfigured") is False


def test_policy_missing_everywhere_is_not_evaluated():
    a, b = dev(policy=None), dev(policy=None)
    assert result("iseppconfigured", page(a, b), "isEPPConfigured") is False
    assert errors("iseppconfigured", page(a, b))


def test_partial_read_cannot_pass_but_a_visible_failure_still_fails():
    partial = page(dev(), dev(), total=500)
    out_ = out("iseppconfigured", partial)
    assert out_["transformedResponse"]["isEPPConfigured"] is False
    assert out_["additionalInfo"]["dataCollection"]["errors"]  # Not evaluated, not a measured fail
    seen_failure = page(dev(), dev(policy=None), total=500)
    out2 = out("iseppconfigured", seen_failure)
    assert out2["transformedResponse"]["isEPPConfigured"] is False
    assert not out2["additionalInfo"]["dataCollection"]["errors"]  # a real, measured failure


def test_complete_read_passes_with_matching_total():
    assert result("iseppconfigured", page(dev(), dev(), total=2), "isEPPConfigured") is True


# ---- keys that are not mapped in the definition (kept as they were)

def test_epp_and_edr_deployed_by_product_name_unchanged():
    assert result("isedrdeployed", page(dev(("protect", "optics"))), "isEDRDeployed") is True
    assert result("isedrdeployed", page(dev(("protect",))), "isEDRDeployed") is False


def test_background_detection_unchanged():
    assert result("isbehavioralmonitoringvalid", page(dev(), dev()), "isBehavioralMonitoringValid") is True
    assert result("isbehavioralmonitoringvalid", page(dev(), dev(bg=False)), "isBehavioralMonitoringValid") is False
    assert result("isbehavioralmonitoringvalid", page(dev(), dev(bg=None)), "isBehavioralMonitoringValid") is False


def test_a_null_placeholder_policy_is_not_an_assignment():
    blank = dev()
    blank["policy"] = {"id": None, "name": None}
    empty = dev()
    empty["policy"] = {"id": "", "name": " "}
    assert result("iseppconfigured", page(blank, empty), "isEPPConfigured") is False
