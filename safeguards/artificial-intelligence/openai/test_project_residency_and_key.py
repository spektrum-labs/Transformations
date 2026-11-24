"""isDataResidencyEnforced and isEncryptionKeyManaged read GET /v1/organization/projects.

True only from a complete read of active projects that all show the setting. A project that
shows it is off (GLOBAL residency, a null external_key_id) is False. Everything that proves
nothing -- refusals, unrecognised bodies, a partial read, no active project, a missing field,
an exception inside the transform -- is Not evaluated: the criterion is None and
additionalInfo.dataCollection.status is "error". Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
RESIDENCY = "isDataResidencyEnforced"
CMK = "isEncryptionKeyManaged"


def load(filename):
    spec = importlib.util.spec_from_file_location("oai_" + filename[:-3], os.path.join(HERE, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def residency():
    return load("isdataresidencyenforced.py")


def cmk():
    return load("isencryptionkeymanaged.py")


class Poisoned(dict):
    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


def lst(items, has_more=False):
    return {"object": "list", "data": list(items), "has_more": has_more}


def project(pid, **fields):
    p = {"id": pid, "object": "organization.project", "name": "Project " + pid,
         "created_at": 1700000000, "archived_at": None, "status": "active"}
    p.update(fields)
    return p


def refusal(status):
    return {"error": True, "status": "Error", "statusCode": status,
            "message": "Incorrect API key provided: sk-admin-SECRETISH"}


def enriched(body):
    return {"data": body, "validation": {"status": "unknown", "errors": [], "warnings": []}}


ARCHIVED_GLOBAL = project("proj_old", residency="GLOBAL", external_key_id=None,
                          archived_at=1700000500, status="archived")

PROVES_NOTHING = [
    ("401", lambda: refusal(401)),
    ("403", lambda: refusal(403)),
    ("404", lambda: refusal(404)),
    ("429", lambda: refusal(429)),
    ("OpenAI error object", lambda: {"error": {"message": "Incorrect API key provided: sk-admin-SECRETISH",
                                               "type": "invalid_request_error", "code": "invalid_api_key"}}),
    ("no projects", lambda: lst([])),
    ("only archived projects", lambda: lst([ARCHIVED_GLOBAL])),
    ("more pages", lambda: lst([project("proj_a", residency="EU_STORAGE_PROCESSING",
                                        external_key_id="ekm_key_a")], has_more=True)),
    ("has_more missing", lambda: {"object": "list", "data": [project("proj_a", residency="EU_STORAGE_PROCESSING",
                                                                     external_key_id="ekm_key_a")]}),
    ("empty dict", lambda: {}),
    ("None", lambda: None),
    ("bare list", lambda: [project("proj_a")]),
    ("not JSON", lambda: "not json"),
    ("poisoned", lambda: Poisoned()),
]


class Shared:
    module = None
    key = None

    def call(self, body):
        return self.module().transform(body)

    def assert_not_evaluated(self, out):
        self.assertIsNone(out["transformedResponse"][self.key])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertTrue(all(isinstance(e, str) and e for e in collection["errors"]))
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def assert_verdict(self, out, value):
        self.assertIs(out["transformedResponse"][self.key], value)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_reads_that_prove_nothing_are_not_evaluated(self):
        for label, body in PROVES_NOTHING:
            for form_label, form in (("bare", body), ("enriched", lambda body=body: enriched(body()))):
                with self.subTest(body=label, form=form_label):
                    self.assert_not_evaluated(self.call(form()))

    def test_refusal_keeps_the_http_status_and_does_not_echo_vendor_text(self):
        for status in (401, 403, 404, 429):
            with self.subTest(status=status):
                out = self.call(refusal(status))
                self.assertEqual(out["transformedResponse"]["httpStatus"], status)
                self.assertNotIn("SECRETISH", repr(out))


class DataResidency(Shared, unittest.TestCase):
    module = staticmethod(residency)
    key = RESIDENCY

    def test_every_active_project_in_a_region_is_true(self):
        body = lst([project("proj_a", residency="EU_STORAGE_PROCESSING"),
                    project("proj_b", residency="US_STORAGE_PROCESSING"),
                    ARCHIVED_GLOBAL])
        for form in (body, enriched(body)):
            out = self.call(form)
            self.assert_verdict(out, True)
            self.assertEqual(out["transformedResponse"]["activeProjects"], 2)
            self.assertEqual(out["additionalInfo"]["evaluation"]["additionalFindings"], [])

    def test_one_global_project_is_false(self):
        out = self.call(lst([project("proj_a", residency="EU_STORAGE_PROCESSING"),
                            project("proj_b", residency="GLOBAL")]))
        self.assert_verdict(out, False)
        self.assertEqual(out["transformedResponse"]["globalProjects"], 1)
        self.assertIn("Project proj_b", out["additionalInfo"]["evaluation"]["failReasons"][0])

    def test_global_is_false_even_when_another_project_is_unreadable(self):
        out = self.call(lst([project("proj_a"), project("proj_b", residency="global")]))
        self.assert_verdict(out, False)

    def test_missing_or_blank_residency_is_not_evaluated(self):
        for value in (None, "", 7):
            with self.subTest(value=value):
                fields = {} if value is None else {"residency": value}
                out = self.call(lst([project("proj_a", residency="EU_STORAGE_PROCESSING"),
                                    project("proj_b", **fields)]))
                self.assert_not_evaluated(out)

    def test_storage_only_region_passes_with_a_finding(self):
        out = self.call(lst([project("proj_a", residency="JP_STORAGE")]))
        self.assert_verdict(out, True)
        findings = out["additionalInfo"]["evaluation"]["additionalFindings"]
        self.assertEqual(len(findings), 1)
        self.assertIn("JP_STORAGE", findings[0])


class CustomerManagedKey(Shared, unittest.TestCase):
    module = staticmethod(cmk)
    key = CMK

    def test_every_active_project_with_a_key_is_true(self):
        body = lst([project("proj_a", external_key_id="ekm_key_a"),
                    project("proj_b", external_key_id="ekm_key_b"),
                    ARCHIVED_GLOBAL])
        for form in (body, enriched(body)):
            out = self.call(form)
            self.assert_verdict(out, True)
            self.assertEqual(out["transformedResponse"]["activeProjects"], 2)

    def test_a_project_without_a_key_is_false(self):
        for value in (None, "", "  "):
            with self.subTest(value=value):
                out = self.call(lst([project("proj_a", external_key_id="ekm_key_a"),
                                    project("proj_b", external_key_id=value)]))
                self.assert_verdict(out, False)
                self.assertEqual(out["transformedResponse"]["unmanagedProjects"], 1)

    def test_missing_or_odd_field_is_not_evaluated(self):
        for fields in ({}, {"external_key_id": 12}, {"external_key_id": {"id": "ekm_key_b"}}):
            with self.subTest(fields=fields):
                out = self.call(lst([project("proj_a", external_key_id="ekm_key_a"), project("proj_b", **fields)]))
                self.assert_not_evaluated(out)


if __name__ == "__main__":
    unittest.main()
