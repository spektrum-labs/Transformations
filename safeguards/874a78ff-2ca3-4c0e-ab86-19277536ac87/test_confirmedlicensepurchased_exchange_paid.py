"""confirmedLicensePurchased (Exchange): a mailbox plan counts only when it was purchased.

subscribedSkus has no trial flag, so the two-read wiring also reads directory/subscriptions and hands both bodies
over as {"subscribedSkus": ..., "subscriptions": ...}. A trial, a not-enabled subscription or a no-cost SKU is not
a purchase. A mailbox SKU whose subscription cannot be read is Not evaluated, never a pass. All data is synthetic.
"""
import importlib.util
import json
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("exlic_paid", Path(__file__).with_name("confirmedlicensepurchased_exchange.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
KEY = "confirmedLicensePurchased"

MAIL_ID = "00000000-0000-4000-8000-0000000000a1"
OTHER_ID = "00000000-0000-4000-8000-0000000000b2"
NEXT = "https://graph.example.invalid/v1.0/directory/subscriptions?$skiptoken=2"


def sku(part, sku_id, plans=("EXCHANGE_S_ENTERPRISE",), status="Enabled", enabled=25):
    return {"skuId": sku_id, "skuPartNumber": part, "capabilityStatus": status, "prepaidUnits": {"enabled": enabled},
            "servicePlans": [{"servicePlanName": p, "provisioningStatus": "Success"} for p in plans]}


def sub(sku_id, trial=False, status="Enabled"):
    return {"id": "sub-" + sku_id[-2:] + ("-t" if trial else ""), "skuId": sku_id, "skuPartNumber": "EXAMPLE",
            "status": status, "isTrial": trial, "totalLicenses": 25}


def body(skus, subs, **extra):
    subscriptions = dict({"value": subs}, **extra) if isinstance(subs, list) else subs
    return {"subscribedSkus": {"value": skus}, "subscriptions": subscriptions}


MAIL = sku("EXAMPLE_MAIL_PLAN", MAIL_ID)


class PaidMailbox(unittest.TestCase):
    def run_check(self, payload):
        return m.transform(payload)

    def verdict(self, payload):
        return self.run_check(payload)["transformedResponse"][KEY]

    def assert_not_evaluated(self, payload):
        out = self.run_check(payload)
        self.assertIsNone(out["transformedResponse"][KEY])
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "error")
        self.assertTrue(out["additionalInfo"]["dataCollection"]["errors"])

    def test_a_paid_enabled_mailbox_subscription_passes(self):
        out = self.run_check(body([MAIL], [sub(MAIL_ID)]))
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")
        self.assertIn("not trial", out["additionalInfo"]["evaluation"]["passReasons"][0])

    def test_wrapped_and_serialised_forms_are_read_alike(self):
        payload = body([MAIL], [sub(MAIL_ID)])
        for wrapped in ({"data": payload, "validation": {"status": "passed", "errors": [], "warnings": []}},
                        {"response": payload}, json.dumps(payload)):
            with self.subTest(form=type(wrapped).__name__):
                self.assertIs(self.verdict(wrapped), True)

    def test_a_trial_only_mailbox_is_a_measured_fail(self):
        out = self.run_check(body([MAIL], [sub(MAIL_ID, trial=True)]))
        self.assertIs(out["transformedResponse"][KEY], False)
        self.assertEqual(out["additionalInfo"]["dataCollection"]["status"], "success")

    def test_a_subscription_that_is_not_enabled_is_a_measured_fail(self):
        for status in ("Suspended", "Expired", "Warning", "LockedOut"):
            with self.subTest(status=status):
                self.assertIs(self.verdict(body([MAIL], [sub(MAIL_ID, status=status)])), False)

    def test_a_trial_beside_a_paid_subscription_of_the_same_sku_passes(self):
        self.assertIs(self.verdict(body([MAIL], [sub(MAIL_ID, trial=True), sub(MAIL_ID)])), True)

    def test_a_paid_mailbox_beside_a_trial_one_passes(self):
        other = sku("EXAMPLE_OTHER_MAIL", OTHER_ID)
        self.assertIs(self.verdict(body([other, MAIL], [sub(OTHER_ID, trial=True), sub(MAIL_ID)])), True)

    def test_a_no_cost_sku_with_a_mailbox_is_never_purchased(self):
        for part in m.FREE_SKU_PARTS:
            free = sku(part, MAIL_ID)
            with self.subTest(part=part):
                self.assertIs(self.verdict(body([free], [sub(MAIL_ID)])), False)
                self.assertIs(self.verdict({"value": [free]}), False)

    def test_no_mailbox_plan_is_a_measured_fail_without_needing_subscriptions(self):
        other = sku("EXAMPLE_NO_MAIL", OTHER_ID, plans=("EXCHANGE_S_FOUNDATION", "EXAMPLE_PLAN"))
        self.assertIs(self.verdict(body([other], [sub(OTHER_ID)])), False)

    def test_a_mailbox_sku_without_a_readable_subscription_is_not_evaluated(self):
        no_flag = sub(MAIL_ID)
        no_flag.pop("isTrial")
        flag_text = dict(sub(MAIL_ID), isTrial="false")
        for label, subs in (("no row for the sku", [sub(OTHER_ID)]), ("trial flag missing", [no_flag]),
                            ("trial flag not a boolean", [flag_text]), ("empty list", []),
                            ("error body", {"error": {"code": "Authorization_RequestDenied"}}),
                            ("not a list", {"value": "x"})):
            with self.subTest(case=label):
                self.assert_not_evaluated(body([MAIL], subs))

    def test_a_mailbox_sku_without_a_sku_id_is_not_evaluated(self):
        bare = dict(MAIL)
        bare.pop("skuId")
        self.assert_not_evaluated(body([bare], [sub(MAIL_ID)]))

    def test_a_subscriptions_page_that_continues_is_not_a_fail(self):
        self.assert_not_evaluated(body([MAIL], [sub(MAIL_ID, trial=True)], **{"@odata.nextLink": NEXT}))
        self.assertIs(self.verdict(body([MAIL], [sub(MAIL_ID)], **{"@odata.nextLink": NEXT})), True)

    def test_a_missing_subscriptions_read_is_not_a_pass(self):
        self.assert_not_evaluated({"subscribedSkus": {"value": [MAIL]}})

    def test_the_single_read_says_the_trial_status_was_not_read(self):
        out = self.run_check({"value": [MAIL]})
        self.assertIs(out["transformedResponse"][KEY], True)
        self.assertTrue(any("Trial status was not read" in r for r in out["additionalInfo"]["evaluation"]["passReasons"]))


if __name__ == "__main__":
    unittest.main()
