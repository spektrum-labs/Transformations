"""Proofpoint Threat Protection checks answer None (not evaluated), never False, when the report cannot answer.

Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status is "error".
Impelix #179: the report window moves from 30 to 7 days, so quiet tenants return empty reports more
often; an empty, error or zero-volume report must read Not evaluated. Synthetic data only.
"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    spec = importlib.util.spec_from_file_location("pptp_" + name, os.path.join(HERE, name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Poisoned(dict):
    """A non-empty object whose every read raises, to drive the transform's except path."""

    def __init__(self):
        super().__init__(poisoned=True)

    def boom(self, *args, **kwargs):
        raise RuntimeError("poisoned read")

    get = __getitem__ = __contains__ = keys = items = values = __iter__ = boom

    def __len__(self):
        return 1


KEYS = {
    "confirmedlicensepurchased": "confirmedLicensePurchased",
    "isantiphishingenabled": "isAntiPhishingEnabled",
    "issafelinksenabled": "isSafeLinksEnabled",
    "issafeattachmentsenabled": "isSafeAttachmentsEnabled",
}
UNMEASURED = {
    "confirmedlicensepurchased": [{"preDeliveryProtectedMessages": 0, "postDeliveryProtectedMessages": 0,
                                   "overallInboundProtection": 0}],
    "isantiphishingenabled": [{"threatCategories": [], "totalVolume": 0},
                              {"threatCategories": [{"name": "spam", "volume": 5}], "totalVolume": 5}],
    "issafelinksenabled": [{"statsByBreakdownValue": []},
                           {"statsByBreakdownValue": [{"breakdownName": "url", "breakdownMessagesTotal": 0}]}],
    "issafeattachmentsenabled": [{"statsByBreakdownValue": []},
                                 {"statsByBreakdownValue": [{"breakdownName": "attachment", "breakdownMessagesTotal": 0}]}],
}
COMMON = [[], {}, {"error": "403 Forbidden"}, {"errors": ["rate limited"]}, "not json {", None, Poisoned()]


class NoneReadsAsNotEvaluated(unittest.TestCase):
    def test_unanswerable_bodies_are_none_with_a_data_collection_error(self):
        for name, key in KEYS.items():
            for body in COMMON + UNMEASURED[name]:
                with self.subTest(transform=name, body=repr(body)[:60]):
                    out = load(name).transform(body)
                    self.assertIsNone(out["transformedResponse"][key])
                    collection = out["additionalInfo"]["dataCollection"]
                    self.assertEqual(collection["status"], "error")
                    self.assertTrue(collection["errors"])

    def test_measured_answers_are_unchanged(self):
        def run(name, body):
            return load(name).transform(body)["transformedResponse"][KEYS[name]]

        self.assertIs(run("confirmedlicensepurchased", {"preDeliveryProtectedMessages": 10,
                                                        "postDeliveryProtectedMessages": 1,
                                                        "overallInboundProtection": 0.99}), True)
        self.assertIs(run("isantiphishingenabled", {"threatCategories": [{"name": "phishing", "volume": 3}],
                                                    "totalVolume": 3}), True)
        links = lambda total, bad: {"statsByBreakdownValue": [{"breakdownName": "url", "breakdownMessagesTotal": total,
                                                                "messagesWithNonRewrittenUrls": bad}]}
        self.assertIs(run("issafelinksenabled", links(100, 1)), True)
        self.assertIs(run("issafelinksenabled", links(100, 50)), False)
        atts = lambda total, prot: {"statsByBreakdownValue": [{"breakdownName": "attachment",
                                                                "breakdownMessagesTotal": total,
                                                                "breakdownProtectedMessagesTotal": prot}]}
        self.assertIs(run("issafeattachmentsenabled", atts(100, 99)), True)
        self.assertIs(run("issafeattachmentsenabled", atts(100, 40)), False)


if __name__ == "__main__":
    unittest.main()
