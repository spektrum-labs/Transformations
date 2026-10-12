"""An error or empty body from Abnormal reads as Not evaluated, never as a failed check.

The three checks answered from /v1/threats/{threatId} and /v1/vendor-cases used to turn an error
envelope, an empty body or an unrecognised body into False. None is "not measured": the criterion
is None and the data-collection status is error, which the evaluator shows as Not evaluated.

A well-formed response that lists nothing (no messages, no vendor cases) keeps its previous
verdict; whether that should also be Not evaluated is a separate product decision. All payloads
here are synthetic.
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

    def test_empty_vendor_case_list_keeps_the_previous_verdict(self):
        self.assertIs(self.verdict(VENDOR, VENDOR, {"vendorCases": [], "pageNumber": 1}), False)
        self.assertIs(self.verdict(VENDOR, VENDOR, []), False)


if __name__ == "__main__":
    unittest.main()
