"""SentinelOne (2bc425fa): every getEndpoints transform scores only a complete agent read; the licence reads every site.

Complete = SentinelOne's pagination block with a numeric totalItems, no nextCursor left, no IS `truncated` marker,
and at least totalItems agents. Carlex (2026-09-29) has 1,056 agents under one account with 8 sites: the old
definition read one page of 1,000, and the licence call read one site. Shapes below are the IS run_with_override
response for GET /agents and GET /sites (result -> data, pagination, apiResponse) and the Token-Service new-format
envelope {"data": <that response>, "validation": {...}}.
"""
import importlib.util
import unittest
from pathlib import Path

AGENT_KEYS = ["requiredCoveragePercentage", "requiredConfigurationPercentage", "isEPPEnabled",
              "isEPPLoggingEnabled", "isEPPEnabledForCriticalSystems", "isEPPDeployed"]


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent(i):
    return {"id": str(i), "computerName": "host" + str(i), "mitigationMode": "protect", "activeProtection": ["edr"],
            "isActive": True, "isUninstalled": False, "isDecommissioned": False, "isUpToDate": True,
            "machineType": "desktop"}


def is_response(agents, total, cursor=None, truncated=None):
    pagination = {"totalItems": total, "nextCursor": cursor}
    if truncated is not None:
        pagination["truncated"] = truncated
    return {"result": {"data": agents, "pagination": pagination,
                       "apiResponse": {"data": agents, "pagination": pagination}}}


def ts(raw):
    return {"data": raw, "validation": {"status": "skipped", "errors": [], "warnings": []}}


class AgentReads(unittest.TestCase):
    mods = {k: load(k) for k in AGENT_KEYS}

    def value(self, key, payload):
        out = self.mods[key].transform(payload)
        return out["transformedResponse"][key], out["additionalInfo"]["dataCollection"]["status"]

    def test_complete_multi_page_read_is_scored(self):
        agents = [agent(i) for i in range(1056)]
        for key in AGENT_KEYS:
            v, dc = self.value(key, ts(is_response(agents, 1056)))
            self.assertIsNotNone(v, key)
            self.assertEqual(dc, "success", key)

    def test_first_page_only_is_not_scored(self):
        agents = [agent(i) for i in range(1000)]
        for key in AGENT_KEYS:
            v, dc = self.value(key, ts(is_response(agents, 1056, cursor="eyJpZCI6IDF9")))
            self.assertIsNone(v, key)
            self.assertEqual(dc, "error", key)

    def test_fewer_than_total_is_not_scored(self):
        agents = [agent(i) for i in range(1000)]
        for key in AGENT_KEYS:
            self.assertEqual(self.value(key, ts(is_response(agents, 1056))), (None, "error"), key)

    def test_truncated_merge_is_not_scored(self):
        agents = [agent(i) for i in range(50)]
        for key in AGENT_KEYS:
            self.assertEqual(self.value(key, ts(is_response(agents, 50, truncated=True))), (None, "error"), key)

    def test_no_pagination_or_error_is_not_scored(self):
        bodies = [ts([agent(1)]), ts({"data": [agent(1)]}), ts({}), ts(None), {},
                  ts({"result": {"errors": [{"code": 4030010, "title": "Insufficient permissions"}]}}),
                  ts({"error": True, "statusCode": 412, "message": "Required integration credentials are not connected"})]
        for key in AGENT_KEYS:
            for body in bodies:
                self.assertEqual(self.value(key, body), (None, "error"), (key, body))

    def test_measured_zero_fleet_is_not_evaluated(self):
        # A complete read with no agents proves nothing either way (2026-10-02, Collaborative Fund): Unevaluated
        # (None plus a dataCollection reason Token-Service renders as "Not evaluated"), never False or 0%.
        for key in AGENT_KEYS:
            self.assertEqual(self.value(key, ts(is_response([], 0))), (None, "error"), key)

    def test_one_unprotected_agent_flips_the_verdict(self):
        agents = [agent(i) for i in range(20)]
        bad = dict(agents[0], mitigationMode="none", activeProtection=[], isUninstalled=True, isActive=False,
                   isUpToDate=False, machineType="server")
        for key in ["requiredCoveragePercentage", "requiredConfigurationPercentage", "isEPPEnabled",
                    "isEPPLoggingEnabled", "isEPPEnabledForCriticalSystems"]:
            good, _ = self.value(key, ts(is_response(agents, 20)))
            flipped, _ = self.value(key, ts(is_response([bad] + agents[1:], 20)))
            self.assertNotEqual(good, flipped, key)


def site(name, **over):
    s = {"id": name, "name": name, "state": "active", "siteType": "Paid", "totalLicenses": 0, "unlimitedLicenses": True,
         "expiration": "2099-09-13T04:00:00Z", "unlimitedExpiration": False, "sku": "Control", "activeLicenses": 1}
    s.update(over)
    return s


def sites_response(sites, total=None, cursor=None):
    pagination = {"totalItems": len(sites) if total is None else total, "nextCursor": cursor}
    body = {"data": {"allSites": {"activeLicenses": 0, "totalLicenses": 0}, "sites": sites}, "pagination": pagination}
    return {"result": {"data": body["data"], "pagination": pagination, "apiResponse": body}}


class Licence(unittest.TestCase):
    m = load("confirmedLicensePurchased")

    def value(self, payload):
        out = self.m.transform(payload)
        return out["transformedResponse"]["confirmedLicensePurchased"], out["additionalInfo"]["dataCollection"]["status"]

    def test_every_site_in_account_paid_passes(self):
        self.assertEqual(self.value(ts(sites_response([site("s" + str(i)) for i in range(8)]))), (True, "success"))

    def test_one_trial_site_fails(self):
        sites = [site("s" + str(i)) for i in range(7)] + [site("trial", siteType="Trial")]
        self.assertEqual(self.value(ts(sites_response(sites))), (False, "success"))

    def test_single_site_list_and_legacy_single_object_agree(self):
        one = site("only")
        legacy = {"result": {"accountId": "1", "apiResponse": {"data": one}}}
        self.assertEqual(self.value(ts(sites_response([one]))), (True, "success"))
        self.assertEqual(self.value(ts(legacy)), (True, "success"))
        expired = site("only", expiration="2020-01-01T00:00:00Z")
        self.assertEqual(self.value(ts(sites_response([expired]))), (False, "success"))

    def test_partial_or_missing_site_list_is_not_scored(self):
        for body in [sites_response([site("a")], total=8), sites_response([site("a")], cursor="abc"),
                     sites_response([]), {}, {"errors": [{"code": 4030010}]}, None]:
            self.assertEqual(self.value(ts(body)), (None, "error"), body)


if __name__ == "__main__":
    unittest.main()
