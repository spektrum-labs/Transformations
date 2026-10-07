"""isAutoForwardDisabled reads Cloud Identity Policy API gmail.* policies (getGmailPolicies).

Fixture shape mirrors a stored Workspace Gmail policy read, with every id, customer and group replaced by
synthetic values: Integration-Service stringifies scalars ("False", "201.00183"); Google's SYSTEM defaults
sit on the top-level org unit. Most tenants also get a SYSTEM gmail.auto_forwarding policy (allowed) there;
some get none, and that list is not evaluated.
"""
import ast
import copy
import importlib.util
import json
import unittest
from pathlib import Path

PATH = Path(__file__).with_name("isautoforwarddisabled.py")
KEY = "isAutoForwardDisabled"
ROOT = "orgUnits/0000root0000a"
CHILD = "orgUnits/0000child0001"
GROUP = "groups/0000group0001"


def load():
    spec = importlib.util.spec_from_file_location("isautoforwarddisabled", PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ou_query(ou):
    return "entity.org_units.exists(org_unit, org_unit.org_unit_id == orgUnitId('" + ou.split("/")[1] + "'))"


def forwarding(enable, ou=ROOT, order="201.00243", ptype="ADMIN", group=None, query=None):
    pq = {"orgUnit": ou, "sortOrder": order}
    if group:
        pq["group"] = group
        pq["query"] = ("entity.groups.exists(group, group.group_id == groupId('" + group.split("/")[1] + "')) && "
                       + ou_query(ou))
    else:
        pq["query"] = ou_query(ou)
    if query is not None:
        pq["query"] = query
    value = {} if enable is None else {"enableAutoForwarding": enable}
    return {"name": "policies/synthetic01", "customer": "customers/C0synthetic", "policyQuery": pq,
            "setting": {"type": "settings/gmail.auto_forwarding", "value": value}, "type": ptype}


def gmail_default(kind, value, ou=ROOT, ptype="SYSTEM", order="101.00125"):
    return {"name": "policies/synthetic99", "customer": "customers/C0synthetic",
            "policyQuery": {"orgUnit": ou, "query": ou_query(ou), "sortOrder": order},
            "setting": {"type": "settings/gmail." + kind, "value": value}, "type": ptype}


BASE = [
    gmail_default("confidential_mode", {"enableConfidentialMode": "True"}),
    gmail_default("external_recipient_warning", {"enabled": "True"}),
    gmail_default("mail_delegation", {"enableMailDelegation": "False"}, ptype="ADMIN", order="201.00243"),
]


def body(*extra):
    return {"policies": copy.deepcopy(BASE) + [copy.deepcopy(p) for p in extra]}


SYSTEM_ALLOW = forwarding("True", ptype="SYSTEM", order="101.00125")


def ts_is_equals_true(value):
    """Token-Service isEquals true: only a real True passes."""
    return value is True


class AutoForwardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = load()

    def run_t(self, payload):
        out = self.t.transform(payload)
        return out["transformedResponse"][KEY], out

    def assert_unevaluated(self, payload):
        value, out = self.run_t(payload)
        self.assertIsNone(value, out)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        self.assertFalse(ts_is_equals_true(value))
        return out

    # no auto_forwarding policy in a complete Gmail list: no default is assumed
    def test_no_forwarding_policy_is_unevaluated(self):
        out = self.assert_unevaluated(body())
        self.assertIn("No gmail.auto_forwarding policy", out["additionalInfo"]["dataCollection"]["errors"][0])

    def test_system_default_allow_alone_is_false(self):
        value, out = self.run_t(body(SYSTEM_ALLOW))
        self.assertIs(value, False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    # pass
    def test_root_off_is_true(self):
        value, out = self.run_t(body(forwarding("False")))
        self.assertIs(value, True)
        self.assertTrue(ts_is_equals_true(value))

    def test_root_off_native_bool_and_snake_case(self):
        self.assertIs(self.run_t(body(forwarding(False)))[0], True)
        snake = forwarding(None)
        snake["setting"]["value"] = {"enable_auto_forwarding": "False"}
        self.assertIs(self.run_t(body(snake))[0], True)

    def test_root_off_with_child_off_is_true(self):
        self.assertIs(self.run_t(body(forwarding("False"), forwarding("False", ou=CHILD, order="203")))[0], True)

    def test_system_allow_overridden_by_later_admin_off_is_true(self):
        payload = body(forwarding("True", ptype="SYSTEM", order="101.00125"), forwarding("False"))
        value, out = self.run_t(payload)
        self.assertIs(value, True)
        self.assertEqual(out["additionalInfo"]["transformation"]["inputSummary"]["overriddenAllowingPolicies"], 1)

    def test_wrapped_string_and_bytes(self):
        payload = body(forwarding("False"))
        self.assertIs(self.run_t(json.dumps(payload))[0], True)
        self.assertIs(self.run_t(json.dumps(payload).encode("utf-8"))[0], True)
        self.assertIs(self.run_t({"result": {"apiResponse": copy.deepcopy(payload)}})[0], True)

    # fail
    def test_root_on_is_false(self):
        self.assertIs(self.run_t(body(forwarding("True")))[0], False)

    def test_field_absent_in_value_is_unevaluated(self):
        # No default is assumed: proto3-style serializers drop false-valued fields, so {} could mean off.
        self.assert_unevaluated(body(forwarding(None)))
        self.assert_unevaluated(body(forwarding("False"), forwarding(None, ptype="SYSTEM", order="101.00125")))
        self.assertIs(self.run_t(body(forwarding(None, ou=CHILD, order="203"), forwarding("True", ou=CHILD, order="204"),
                                      SYSTEM_ALLOW))[0], False)

    def test_child_ou_override_allows_is_false(self):
        value, out = self.run_t(body(forwarding("False"), forwarding("True", ou=CHILD, order="203")))
        self.assertIs(value, False)
        self.assertIn(CHILD, out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_group_override_allows_is_false(self):
        value, out = self.run_t(body(forwarding("False"), forwarding("True", group=GROUP, order="399.00018")))
        self.assertIs(value, False)
        self.assertIn("group " + GROUP, out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_child_off_only_with_system_root_allow_is_false(self):
        self.assertIs(self.run_t(body(SYSTEM_ALLOW, forwarding("False", ou=CHILD, order="203")))[0], False)

    def test_child_off_only_without_root_policy_is_unevaluated(self):
        self.assert_unevaluated(body(forwarding("False", ou=CHILD, order="203")))

    def test_conditional_later_off_leaves_allow_in_force_false(self):
        licensed = ou_query(ROOT) + " && entity.licenses.exists(license, license in ['/product/P/sku/1'])"
        value, out = self.run_t(body(SYSTEM_ALLOW, forwarding("False", query=licensed)))
        self.assertIs(value, False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_query_naming_another_org_unit_is_not_a_plain_root_off(self):
        mismatched = forwarding("False", query=ou_query(CHILD))
        self.assertIs(self.run_t(body(SYSTEM_ALLOW, mismatched))[0], False)
        self.assert_unevaluated(body(mismatched))
        wrong_group = forwarding("False", group=GROUP, order="400")
        wrong_group["policyQuery"]["group"] = "groups/0000group0002"
        allow = forwarding("True", group="groups/0000group0002", order="300")
        self.assertIs(self.run_t(body(forwarding("False"), allow, wrong_group))[0], False)
        right_group = forwarding("False", group="groups/0000group0002", order="400")
        self.assertIs(self.run_t(body(forwarding("False"), allow, right_group))[0], True)

    def test_lower_order_off_does_not_override_allow(self):
        payload = body(forwarding("False", order="150"), forwarding("True", order="201.00243"))
        self.assertIs(self.run_t(payload)[0], False)

    # not evaluated
    def test_empty_inputs_are_unevaluated(self):
        for payload in [{}, "{}", "", b"", "   ", {"policies": []}, {"result": {}}, []]:
            self.assert_unevaluated(payload)

    def test_none_is_unevaluated(self):
        self.assert_unevaluated(None)

    def test_error_bodies_are_unevaluated(self):
        scope = {"error": {"code": 403, "message": "Request had insufficient authentication scopes.",
                           "status": "PERMISSION_DENIED"}}
        out = self.assert_unevaluated(scope)
        self.assertIn("cloud-identity.policies.readonly", out["additionalInfo"]["dataCollection"]["errors"][0])
        for payload in [{"statusCode": 401, "error": "Unauthorized"}, {"status": "Error", "message": "x"},
                        {"error": True, "errorType": "pagination_incomplete", "statusCode": 502}]:
            self.assert_unevaluated(payload)

    def test_wrapper_level_truncation_markers_are_unevaluated(self):
        inner = body(SYSTEM_ALLOW, forwarding("False"))
        self.assertIs(self.run_t(copy.deepcopy(inner))[0], True)
        for payload in [{"response": copy.deepcopy(inner), "paginationTruncated": True},
                        {"result": {"apiResponse": copy.deepcopy(inner), "nextPageToken": "synthetic-token"}},
                        {"paginationStats": {"policies": {"paginationTruncated": True}}, "result": copy.deepcopy(inner)},
                        {"result": {"paginationStats": {"paginationTruncated": "True"}, "apiResponse": copy.deepcopy(inner)}},
                        {"iterateStats": {"complete": False}, "response": copy.deepcopy(inner)}]:
            self.assert_unevaluated(payload)
        sibling = {"data": {"meta": "x"}, "response": copy.deepcopy(inner)}
        sibling["response"]["nextPageToken"] = "synthetic-token"
        self.assert_unevaluated(sibling)
        sibling = {"data": {"note": "x"}, "result": {"apiResponse": copy.deepcopy(inner),
                                                     "paginationStats": {"paginationTruncated": True}}}
        self.assert_unevaluated(sibling)
        self.assertIs(self.run_t({"data": {"note": "x"}, "response": copy.deepcopy(inner)})[0], True)
        clean = {"paginationStats": {"policies": {"paginationTruncated": False, "pages": 1}}, "result": copy.deepcopy(inner)}
        self.assertIs(self.run_t(clean)[0], True)

    def test_partial_reads_are_unevaluated(self):
        payload = body(forwarding("False"))
        payload["nextPageToken"] = "synthetic-token"
        self.assert_unevaluated(payload)
        payload = body(forwarding("False"))
        payload["paginationTruncated"] = "True"
        self.assert_unevaluated(payload)

    def test_list_without_gmail_settings_is_unevaluated(self):
        other = gmail_default("x", {})
        other["setting"]["type"] = "settings/security.session_controls"
        self.assert_unevaluated({"policies": [other]})

    def test_unrelated_and_non_policy_records_are_unevaluated(self):
        for payload in [{"hello": "world"}, {"policies": [{"id": 1}]},
                        {"policies": body()["policies"] + ["not a policy"]}]:
            self.assert_unevaluated(payload)

    def test_root_unknown_is_unevaluated(self):
        payload = {"policies": [forwarding("False"),
                                gmail_default("mail_delegation", {"enableMailDelegation": "False"},
                                              ptype="ADMIN", order="201")]}
        self.assert_unevaluated(payload)
        two_roots = body(forwarding("False"), gmail_default("web_offline", {"enabled": "True"}, ou=CHILD))
        self.assert_unevaluated(two_roots)

    def test_unreadable_value_or_org_unit_is_unevaluated(self):
        bad = forwarding("sometimes")
        self.assert_unevaluated(body(bad))
        no_ou = forwarding("False")
        del no_ou["policyQuery"]["orgUnit"]
        self.assert_unevaluated(body(forwarding("False"), no_ou))
        no_value = forwarding("False")
        del no_value["setting"]["value"]
        self.assert_unevaluated(body(no_value))

    def test_conditional_or_unordered_root_off_is_unevaluated(self):
        licensed = ou_query(ROOT) + " && entity.licenses.exists(license, license in ['/product/P/sku/1'])"
        self.assert_unevaluated(body(forwarding("False", query=licensed)))
        self.assert_unevaluated(body(forwarding("False", order=None)))

    def test_transformation_error_is_unevaluated(self):
        original = self.t.evaluate
        try:
            self.t.evaluate = lambda policies, root: (_ for _ in ()).throw(RuntimeError("boom"))
            out = self.assert_unevaluated(body(forwarding("False")))
            self.assertEqual(out["additionalInfo"]["transformation"]["status"], "error")
        finally:
            self.t.evaluate = original

    def test_never_a_non_boolean_verdict(self):
        for payload in [body(), body(forwarding("False")), {}, None, {"hello": "world"}]:
            self.assertIn(self.run_t(copy.deepcopy(payload))[0], [True, False, None])


def test_no_call_the_token_service_sandbox_refuses():
    src = PATH.read_text()
    denied = {"__import__", "eval", "exec", "compile", "open", "file", "input", "raw_input", "execfile", "reload",
              "__builtins__", "getattr", "setattr", "delattr", "hasattr", "globals", "locals", "vars", "dir"}
    hits = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
            if name in denied:
                hits.append((name, node.lineno))
    assert hits == []


if __name__ == "__main__":
    unittest.main()
