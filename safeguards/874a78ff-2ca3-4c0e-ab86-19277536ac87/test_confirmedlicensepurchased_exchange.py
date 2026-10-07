"""MS 365 confirmedLicensePurchased (Exchange) reads subscribedSkus for an enabled Exchange Online plan.

Free SKUs every tenant carries (FLOW_FREE, POWER_BI_STANDARD) include EXCHANGE_S_FOUNDATION, which is not a
mailbox; the old affirmative_signal rule passed on any SKU row.
"""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("exlic", Path(__file__).with_name("confirmedlicensepurchased_exchange.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
KEY = "confirmedLicensePurchased"


def sku(part, plans, status="Enabled", enabled=25):
    return {"skuPartNumber": part, "capabilityStatus": status, "prepaidUnits": {"enabled": enabled},
            "servicePlans": [{"servicePlanName": p, "provisioningStatus": "Success"} for p in plans]}


class ExchangeLicence(unittest.TestCase):
    def res(self, payload):
        return m.transform(payload)["transformedResponse"][KEY]

    def test_e3_passes(self):
        self.assertIs(self.res({"value": [sku("ENTERPRISEPACK", ["EXCHANGE_S_ENTERPRISE", "SHAREPOINTENTERPRISE"])]}), True)

    def test_free_skus_only_fail(self):
        body = {"value": [sku("FLOW_FREE", ["FLOW_P2_VIRAL", "EXCHANGE_S_FOUNDATION"], enabled=10000),
                          sku("POWER_BI_STANDARD", ["BI_AZURE_P0", "EXCHANGE_S_FOUNDATION"], enabled=1000000)]}
        self.assertIs(self.res(body), False)

    def test_suspended_exchange_fails(self):
        self.assertIs(self.res({"value": [sku("EXCHANGESTANDARD", ["EXCHANGE_S_STANDARD"], status="Suspended")]}), False)

    def test_empty_and_errors_fail(self):
        self.assertIs(self.res({"value": []}), False)
        self.assertIs(self.res({"error": {"code": "Authorization_RequestDenied"}}), False)
        self.assertIs(self.res({}), False)


class AuditLogSearchEmitsEmailLogging(unittest.TestCase):
    # J.J. 2026-09-29: the email-logging criteria read Purview audit log search (mip_search_auditlog),
    # not mailbox auditing (exo_mailboxaudit), which now answers isMailboxAuditingEnabled only.
    spec = importlib.util.spec_from_file_location("als", Path(__file__).with_name("isauditlogsearchenabled.py"))
    mb = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mb)

    def res(self, score):
        body = {"value": [{"controlScores": [{"controlName": "mip_search_auditlog", "scoreInPercentage": score}]}]}
        return self.mb.transform(body)["transformedResponse"]

    def test_full_score_passes_both_keys(self):
        r = self.res(100.0)
        self.assertIs(r["isEmailSecurityLoggingEnabled"], True)
        self.assertIs(r["isEmailLoggingEnabled"], True)

    def test_partial_score_fails(self):
        self.assertIs(self.res(50.0)["isEmailSecurityLoggingEnabled"], False)

    def test_sign_in_log_body_fails(self):
        body = {"value": [{"id": "s1", "createdDateTime": "2026-09-28T00:00:00Z", "userPrincipalName": "a@b.c"}]}
        self.assertIs(self.mb.transform(body)["transformedResponse"]["isEmailSecurityLoggingEnabled"], False)

if __name__ == "__main__":
    unittest.main()
