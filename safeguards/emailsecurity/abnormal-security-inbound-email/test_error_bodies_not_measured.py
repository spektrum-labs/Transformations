"""An error or empty body from Abnormal reads as Not evaluated, never as a failed check.

The three checks answered from /v1/threats/{threatId} and /v1/vendor-cases used to turn an error
envelope, an empty body or an unrecognised body into False. None is "not measured": the criterion
is None and the data-collection status is error, which the evaluator shows as Not evaluated.

A well-formed response that lists no messages keeps its previous verdict. A well-formed response
that lists no vendor cases is Not evaluated: vendor cases only exist once detection has flagged
something, so a quiet tenant cannot be told from a tenant with detection off. All payloads here are
synthetic.
"""
import importlib.util
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
VALIDATION = {"status": "skipped", "errors": [], "warnings": []}

IMPOSTER = "isImposterEmailDetectionEnabled"
CAMPAIGN = "isThreatCampaignCorrelationEnabled"
VENDOR = "isVendorEmailCompromiseDetectionEnabled"

HOST_TEXT = "http://internal-service.example:8083/v1/run/example"
ERROR_BODY = {"error": True, "message": "Integration execution error: HTTP 500: Server Error, url='" + HOST_TEXT + "'"}
ERRORS_LIST_BODY = {"errors": [{"code": "forbidden"}]}


def load(name):
    spec = importlib.util.spec_from_file_location("abnormal_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def threat(count=2):
    return {
        "threatId": "11111111-1111-1111-1111-111111111111",
        "messages": [
            {"threatId": "11111111-1111-1111-1111-111111111111", "attackType": "Phishing: Credential",
             "attackStrategy": "Impersonation", "attackedParty": "VIP", "impersonatedParty": "Example Co"}
            for _ in range(count)
        ],
    }


def enveloped(body):
    return {"data": body, "validation": VALIDATION}


BAD_BODIES = [
    ("error flag", ERROR_BODY),
    ("errors list", ERRORS_LIST_BODY),
    ("empty object", {}),
    ("none", None),
    ("empty string", ""),
    ("unrelated json", {"hello": "world"}),
    ("enveloped error", enveloped(ERROR_BODY)),
    ("enveloped empty", enveloped({})),
]


class ErrorBodiesAreNotMeasured(unittest.TestCase):
    def check_not_measured(self, name, key, body):
        out = load(name).transform(body)
        self.assertIsNone(out["transformedResponse"][key])
        collection = out["additionalInfo"]["dataCollection"]
        self.assertEqual(collection["status"], "error")
        self.assertTrue(collection["errors"])
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])
        self.assertNotIn("internal-service", json.dumps(out))  # the vendor's error text is never echoed

    def test_imposter(self):
        for label, body in BAD_BODIES:
            with self.subTest(body=label):
                self.check_not_measured(IMPOSTER, IMPOSTER, body)

    def test_campaign(self):
        for label, body in BAD_BODIES + [("bare list", [threat()["messages"][0]]), ("messages not a list", {"threatId": "t", "messages": "x"})]:
            with self.subTest(body=label):
                self.check_not_measured(CAMPAIGN, CAMPAIGN, body)

    def test_vendor_cases(self):
        for label, body in BAD_BODIES + [("data not a list", {"data": "x"})]:
            with self.subTest(body=label):
                self.check_not_measured(VENDOR, VENDOR, body)


class WellFormedResponsesKeepTheirVerdict(unittest.TestCase):
    def verdict(self, name, key, body):
        out = load(name).transform(body)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        return out["transformedResponse"][key]

    def test_threat_detail_with_messages_is_measured(self):
        self.assertIs(self.verdict(IMPOSTER, IMPOSTER, threat()), True)
        self.assertIs(self.verdict(IMPOSTER, IMPOSTER, enveloped(threat())), True)
        self.assertIs(self.verdict(CAMPAIGN, CAMPAIGN, threat()), True)
        self.assertIs(self.verdict(CAMPAIGN, CAMPAIGN, enveloped(threat())), True)

    def test_unclassified_messages_still_fail(self):
        body = {"threatId": "t", "messages": [{"threatId": "t"}]}
        self.assertIs(self.verdict(IMPOSTER, IMPOSTER, body), False)
        self.assertIs(self.verdict(CAMPAIGN, CAMPAIGN, body), False)

    def test_empty_message_list_keeps_the_previous_verdict(self):
        body = {"threatId": "t", "messages": []}
        self.assertIs(self.verdict(IMPOSTER, IMPOSTER, body), False)
        self.assertIs(self.verdict(CAMPAIGN, CAMPAIGN, body), False)

    def test_vendor_cases_present_is_true_in_every_shape(self):
        cases = [{"vendorCaseId": "1"}, {"vendorCaseId": "2"}]
        self.assertIs(self.verdict(VENDOR, VENDOR, {"vendorCases": cases}), True)
        self.assertIs(self.verdict(VENDOR, VENDOR, {"data": cases}), True)
        self.assertIs(self.verdict(VENDOR, VENDOR, cases), True)
        self.assertIs(self.verdict(VENDOR, VENDOR, enveloped({"vendorCases": cases})), True)

    def test_empty_vendor_case_list_is_not_evaluated(self):
        for label, body in [
            ("wrapped", {"vendorCases": [], "pageNumber": 1}),
            ("bare list", []),
            ("data", {"data": []}),
            ("enveloped", enveloped({"vendorCases": []})),
        ]:
            with self.subTest(shape=label):
                out = load(VENDOR).transform(body)
                self.assertIsNone(out["transformedResponse"][VENDOR])
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
                self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])


class MalformedListItemsAreNotRecords(unittest.TestCase):
    """Items that are not objects are never counted as records, and a non-string label is never a label."""

    def run_check(self, name, body):
        return load(name).transform(body)

    def assert_not_measured(self, out, key):
        self.assertIsNone(out["transformedResponse"][key])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")

    def test_list_with_no_objects_is_not_measured(self):
        junk = [1, "x", None, ["y"]]
        self.assert_not_measured(self.run_check(VENDOR, {"vendorCases": junk}), VENDOR)
        self.assert_not_measured(self.run_check(VENDOR, junk), VENDOR)
        self.assert_not_measured(self.run_check(IMPOSTER, {"threatId": "t", "messages": junk}), IMPOSTER)
        self.assert_not_measured(self.run_check(CAMPAIGN, {"threatId": "t", "messages": junk}), CAMPAIGN)

    def test_non_object_items_are_not_counted_as_cases(self):
        out = self.run_check(VENDOR, {"vendorCases": [1, "x", {"vendorCaseId": "1"}]})
        self.assertIs(out["transformedResponse"][VENDOR], True)
        self.assertEqual(out["transformedResponse"]["vendorCaseCount"], 1)

    def test_non_object_items_are_not_counted_as_messages(self):
        good = threat(1)
        good["messages"] = ["x", None] + good["messages"]
        for name in (IMPOSTER, CAMPAIGN):
            with self.subTest(check=name):
                out = self.run_check(name, good)
                self.assertIs(out["transformedResponse"][name], True)
        self.assertEqual(self.run_check(IMPOSTER, good)["transformedResponse"]["totalMessagesEvaluated"], 1)
        self.assertEqual(self.run_check(CAMPAIGN, good)["transformedResponse"]["messageCount"], 1)

    def test_non_string_labels_do_not_crash_and_do_not_classify(self):
        for bad in (5, ["Phishing"], {"a": 1}, True):
            with self.subTest(attackType=bad):
                body = {"threatId": "t", "messages": [{"threatId": "t", "attackType": bad, "attackStrategy": bad,
                                                       "impersonatedParty": bad}]}
                out = self.run_check(IMPOSTER, body)
                self.assertIs(out["transformedResponse"][IMPOSTER], False)
                self.assertEqual(out["transformedResponse"]["classifiedMessages"], 0)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
                out = self.run_check(CAMPAIGN, {"threatId": "t", "messages": [{"threatId": "t", "attackType": bad}]})
                self.assertIs(out["transformedResponse"][CAMPAIGN], False)


class OnlyRealCaseRecordsAreCounted(unittest.TestCase):
    """A vendor case is an object with a real vendorCaseId. An error-shaped or empty object in the list
    is not a case: it is not counted, and a list with no real case in it is not measured."""

    def run_vendor(self, body):
        return load(VENDOR).transform(body)

    def test_error_shaped_items_are_not_cases(self):
        for label, items in [
            ("error object", [{"error": "x"}]),
            ("error flag object", [{"error": True, "message": "boom"}]),
            ("empty object", [{}]),
            ("no id", [{"message": "x"}, {"vendorCaseId": None}]),
            ("blank id", [{"vendorCaseId": ""}, {"vendorCaseId": "   "}]),
            ("boolean id", [{"vendorCaseId": True}]),
            ("id is an object", [{"vendorCaseId": {"a": 1}}]),
        ]:
            for shape, body in [("wrapped", {"vendorCases": items}), ("bare", items), ("data", {"data": items})]:
                with self.subTest(items=label, shape=shape):
                    out = self.run_vendor(body)
                    self.assertIsNone(out["transformedResponse"][VENDOR])
                    self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                    self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
                    self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_only_real_records_are_counted_next_to_junk(self):
        body = {"vendorCases": [{"error": "x"}, {"vendorCaseId": "1"}, {}, {"vendorCaseId": 7}, {"vendorCaseId": ""}]}
        out = self.run_vendor(body)
        self.assertIs(out["transformedResponse"][VENDOR], True)
        self.assertEqual(out["transformedResponse"]["vendorCaseCount"], 2)

    def test_a_numeric_case_id_is_a_real_record(self):
        out = self.run_vendor({"vendorCases": [{"vendorCaseId": 42}]})
        self.assertIs(out["transformedResponse"][VENDOR], True)
        self.assertEqual(out["transformedResponse"]["vendorCaseCount"], 1)

    def test_the_empty_list_is_not_evaluated_and_still_reports_the_zero_count(self):
        out = self.run_vendor({"vendorCases": []})
        self.assertIsNone(out["transformedResponse"][VENDOR])
        self.assertEqual(out["transformedResponse"]["vendorCaseCount"], 0)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


class VendorCaseValidationAndPaging(unittest.TestCase):
    """A body that failed input validation, and an empty first page that says more follows, prove nothing
    about whether the tenant has vendor cases: both are Not evaluated, never False."""

    def run_vendor(self, body):
        return load(VENDOR).transform(body)

    def assert_not_evaluated(self, out):
        self.assertIsNone(out["transformedResponse"][VENDOR])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])
        self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_a_failed_validation_is_not_evaluated(self):
        for status in ["failed", "FAILED", "error", " Failed "]:
            for data in [{"vendorCases": []}, {"vendorCases": [{"vendorCaseId": "1"}]}, []]:
                with self.subTest(status=status, data=data):
                    self.assert_not_evaluated(self.run_vendor(
                        {"data": data, "validation": {"status": status, "errors": [], "warnings": []}}))

    def test_a_validation_that_passed_or_was_skipped_keeps_the_verdict(self):
        for status in ["passed", "success", "skipped", "unknown"]:
            with self.subTest(status=status):
                out = self.run_vendor({"data": {"vendorCases": []}, "validation": {"status": status}})
                self.assertIsNone(out["transformedResponse"][VENDOR])
                out = self.run_vendor({"data": {"vendorCases": [{"vendorCaseId": "1"}]}, "validation": {"status": status}})
                self.assertIs(out["transformedResponse"][VENDOR], True)

    def test_a_validation_that_is_not_an_object_does_not_raise(self):
        for validation in [None, "failed", 5, ["failed"]]:
            with self.subTest(validation=validation):
                out = self.run_vendor({"data": {"vendorCases": []}, "validation": validation})
                self.assertIsNone(out["transformedResponse"][VENDOR])

    def test_an_empty_first_page_with_a_next_page_is_not_evaluated(self):
        for token in [{"nextPageNumber": 2}, {"nextPageNumber": "2"}, {"nextPageToken": "abc"}]:
            for shape, body in [
                ("wrapped", dict({"vendorCases": [], "pageNumber": 1}, **token)),
                ("data", dict({"data": [], "pageNumber": 1}, **token)),
                ("enveloped", {"data": dict({"vendorCases": []}, **token), "validation": {"status": "passed"}}),
            ]:
                with self.subTest(token=token, shape=shape):
                    self.assert_not_evaluated(self.run_vendor(body))

    def test_an_empty_last_page_is_not_evaluated_either(self):
        for token in [{}, {"nextPageNumber": None}, {"nextPageNumber": ""}, {"nextPageToken": None}]:
            with self.subTest(token=token):
                self.assert_not_evaluated(self.run_vendor(dict({"vendorCases": [], "pageNumber": 1}, **token)))

    def test_a_page_with_cases_and_a_next_page_is_still_true(self):
        out = self.run_vendor({"vendorCases": [{"vendorCaseId": "1"}], "pageNumber": 1, "nextPageNumber": 2})
        self.assertIs(out["transformedResponse"][VENDOR], True)

    def test_a_case_id_that_is_nan_or_infinite_is_not_a_case(self):
        for label, body in [
            ("nan", {"vendorCases": [{"vendorCaseId": float("nan")}]}),
            ("inf", {"vendorCases": [{"vendorCaseId": float("inf")}]}),
            ("-inf", {"vendorCases": [{"vendorCaseId": float("-inf")}]}),
            ("json NaN", json.loads('{"vendorCases": [{"vendorCaseId": NaN}, {"vendorCaseId": Infinity}]}')),
        ]:
            with self.subTest(case=label):
                self.assert_not_evaluated(self.run_vendor(body))

    def test_nan_beside_a_real_case_is_ignored(self):
        out = self.run_vendor({"vendorCases": [{"vendorCaseId": float("nan")}, {"vendorCaseId": 7}, {"vendorCaseId": 1.5}]})
        self.assertIs(out["transformedResponse"][VENDOR], True)
        self.assertEqual(out["transformedResponse"]["vendorCaseCount"], 2)


class ZeroVendorCasesIsNotEvaluatedNeverFalse(unittest.TestCase):
    """A successful read with no vendor cases proves nothing about whether detection is on. It must
    never read False (which raises a gap); only real case data gives True."""

    def run_vendor(self, body):
        return load(VENDOR).transform(body)

    def test_no_shape_of_an_empty_case_list_reads_false(self):
        for label, body in [
            ("wrapped", {"vendorCases": []}),
            ("wrapped with paging fields", {"vendorCases": [], "pageNumber": 1, "nextPageNumber": None}),
            ("bare", []),
            ("data", {"data": []}),
            ("enveloped passed", {"data": {"vendorCases": []}, "validation": {"status": "passed"}}),
            ("enveloped skipped", {"data": [], "validation": VALIDATION}),
        ]:
            with self.subTest(shape=label):
                out = self.run_vendor(body)
                self.assertIsNone(out["transformedResponse"][VENDOR])
                self.assertIsNot(out["transformedResponse"][VENDOR], False)
                self.assertEqual(out["transformedResponse"]["vendorCaseCount"], 0)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
                self.assertEqual(out["additionalInfo"]["evaluation"]["passReasons"], [])

    def test_the_reason_is_fixed_text_and_names_no_gap_to_fix(self):
        out = self.run_vendor({"vendorCases": []})
        reasons = out["additionalInfo"]["dataCollection"]["errors"] + out["additionalInfo"]["evaluation"]["failReasons"]
        self.assertTrue(reasons)
        self.assertEqual(out["additionalInfo"]["evaluation"]["recommendations"], [])

    def test_real_case_data_still_gives_true(self):
        out = self.run_vendor({"vendorCases": [{"vendorCaseId": "1"}]})
        self.assertIs(out["transformedResponse"][VENDOR], True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_junk_next_to_nothing_is_still_not_evaluated(self):
        out = self.run_vendor({"vendorCases": [{"error": "x"}, {}]})
        self.assertIsNone(out["transformedResponse"][VENDOR])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")


if __name__ == "__main__":
    unittest.main()
