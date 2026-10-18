"""isActivityAuditTrailEnabled: a read that proves nothing is Not evaluated, never False.

The OpenAI Administration API has no field that says "audit logging is off". The check can only
see events in GET /v1/organization/audit_logs. Events prove logging is on (True). An empty list
cannot tell "logging is off" from "logging is on and nothing was logged yet", so it is Not
evaluated, as are refusals (401/403/404/429), unrecognised bodies and an exception inside the
transform. Not evaluated means the criterion is None and additionalInfo.dataCollection.status is
"error", which Token-Service records as not evaluated. Synthetic data only.
"""
import importlib.util
import os
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = "isActivityAuditTrailEnabled"
NOW = int(time.time())


def load():
    spec = importlib.util.spec_from_file_location("oai_audit_ne", os.path.join(HERE, "isactivityaudittrailenabled.py"))
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


def lst(items, has_more=False):
    return {"object": "list", "data": list(items), "has_more": has_more}


def refusal(status):
    return {"error": True, "status": "Error", "statusCode": status,
            "message": "Incorrect API key provided: sk-admin-SECRETISH"}


def enriched(body):
    return {"data": body, "validation": {"status": "unknown", "errors": [], "warnings": []}}


EVENT = {"id": "audit_log-1", "type": "login.succeeded", "effective_at": NOW - 86400}

NOT_EVALUATED = [
    ("401", lambda: refusal(401)),
    ("403", lambda: refusal(403)),
    ("404", lambda: refusal(404)),
    ("429", lambda: refusal(429)),
    ("OpenAI error object", lambda: {"error": {"message": "Incorrect API key provided: sk-admin-SECRETISH",
                                               "type": "invalid_request_error", "code": "invalid_api_key"}}),
    ("empty audit log", lambda: lst([])),
    ("empty audit log, more pages", lambda: lst([], has_more=True)),
    ("only unreadable entries", lambda: lst([{}, {"id": "x"}, {"type": 3, "id": "y"}])),
    ("empty dict", lambda: {}),
    ("None", lambda: None),
    ("bare list", lambda: [{"id": "x"}]),
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
                with self.subTest(body=label, form=form_label):
                    self.assert_not_evaluated(load().transform(form()))

    def test_refusal_keeps_the_http_status_and_does_not_echo_vendor_text(self):
        for status in (401, 403, 404, 429):
            with self.subTest(status=status):
                out = load().transform(refusal(status))
                self.assertEqual(out["transformedResponse"]["httpStatus"], status)
                self.assertNotIn("SECRETISH", repr(out))
        out = load().transform({"error": {"message": "Incorrect API key provided: sk-admin-SECRETISH"}})
        self.assertNotIn("SECRETISH", repr(out))

    def test_empty_log_reports_the_zero_it_read(self):
        out = load().transform(lst([]))
        self.assertEqual(out["transformedResponse"]["events"], 0)


class ReadableEventsStillPass(unittest.TestCase):
    def test_an_event_is_true(self):
        for form in (lst([EVENT]), enriched(lst([EVENT])), lst([EVENT], has_more=True)):
            with self.subTest(form=form):
                out = load().transform(form)
                self.assertIs(out["transformedResponse"][KEY], True)
                self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")


if __name__ == "__main__":
    unittest.main()
