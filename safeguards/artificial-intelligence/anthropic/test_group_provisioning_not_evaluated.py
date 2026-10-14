"""isGroupProvisioningManaged: a read that proves nothing is Not evaluated, never False.

False is reserved for a readable groups list that shows at least one group maintained directly
inside Claude (source_type "direct"). A refusal (401/403/404/429), an empty or unrecognised
body, a page that says more groups exist, a group whose source_type is missing, and an exception
inside the transform all answer None with additionalInfo.dataCollection.status "error", which
Token-Service records as not evaluated. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "isGroupProvisioningManaged"


def load():
    spec = importlib.util.spec_from_file_location("gpm_ne", os.path.join(HERE, "isgroupprovisioningmanaged.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def group(gid, source="scim"):
    g = {"id": gid, "name": "group-" + gid, "created_at": None, "updated_at": None, "roles": []}
    if source is not None:
        g["source_type"] = source
    return g


def page(groups, has_more=False, next_page=None):
    return {"data": groups, "has_more": has_more, "next_page": next_page}


def refusal(status):
    return {"error": True, "status": "Error", "statusCode": status, "message": "vendor text sk-ant-SECRETISH"}


def enriched(body):
    return {"data": body, "validation": {"status": "unknown", "errors": [], "warnings": []}}


NOT_EVALUATED = [
    ("401", lambda: refusal(401)),
    ("403", lambda: refusal(403)),
    ("404", lambda: refusal(404)),
    ("429", lambda: refusal(429)),
    ("error, no status", lambda: {"error": {"type": "api_error", "message": "boom"}}),
    ("empty page", lambda: page([])),
    ("bare empty list", lambda: []),
    ("empty dict", lambda: {}),
    ("None", lambda: None),
    ("unrecognised dict", lambda: {"unexpected": 1}),
    ("junk rows only", lambda: page(["x", 3, None])),
    ("truncated, all SCIM so far", lambda: page([group("a"), group("b")], has_more=True, next_page="tok")),
    ("group without source_type", lambda: page([group("a"), group("b", source=None)])),
    ("group with unknown source_type", lambda: page([group("a"), group("b", source="mystery")])),
    ("not JSON", lambda: "not json"),
    ("poisoned", lambda: Poisoned()),
]


class ReadsThatProveNothingAreNotEvaluated(unittest.TestCase):
    def assert_not_evaluated(self, out):
        self.assertIsNone(out["transformedResponse"][KEY])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_never_false(self):
        for label, body in NOT_EVALUATED:
            for form_label, form in (("bare", body), ("enriched", lambda body=body: enriched(body()))):
                if label == "poisoned" and form_label == "enriched":
                    continue
                with self.subTest(body=label, form=form_label):
                    self.assert_not_evaluated(load().transform(form()))

    def test_refusal_keeps_the_http_status_and_does_not_echo_vendor_text(self):
        for status in (401, 403, 404, 429):
            with self.subTest(status=status):
                out = load().transform(refusal(status))
                self.assertEqual(out["transformedResponse"]["httpStatus"], status)
                self.assertNotIn("SECRETISH", repr(out))


class ReadableAnswersKeepTheirVerdict(unittest.TestCase):
    def test_all_scim_complete_page_is_true(self):
        out = load().transform(page([group("a"), group("b")]))
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_a_direct_group_is_false(self):
        for label, body in [
            ("complete page", page([group("a"), group("b", source="direct")])),
            ("truncated page still shows a direct group", page([group("b", source="direct")], has_more=True, next_page="t")),
            ("direct next to a group with no source_type", page([group("a", source=None), group("b", source="direct")])),
            ("bare list", [group("a"), group("b", source="direct")]),
        ]:
            with self.subTest(body=label):
                out = load().transform(body)
                self.assertIs(out["transformedResponse"][KEY], False)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
                self.assertEqual(out["transformedResponse"]["directGroups"], sorted(
                    "group-" + g["id"] for g in (body["data"] if isinstance(body, dict) else body)
                    if g.get("source_type") == "direct"))


if __name__ == "__main__":
    unittest.main()
