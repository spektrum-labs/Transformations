# backupsuccessratepercentage.py - Datto SaaS Protection (Kaseya)
#
# Method: getSaasDomains -> GET https://api.datto.com/v1/saas/domains (HTTP Basic: public key / secret key)
# Docs:   https://saasprotection.datto.com/help/M365/Content/Other_Administrative_Tasks/using-rest-api-saas-protection.htm
#         (documented example output: a JSON array, one object per protected domain, with backupStats
#         {activeServicesCount, activeServicesWithRecentBackupCount, backupPercentage}, domain, saasCustomerId,
#         organizationId, seatsUsed, productType, externalSubscriptionId, retentionType})
#         https://saasprotection.datto.com/help/M365/Content/Administrator_requirements/retention.htm
#         (retentionType ICR = Infinite Cloud Retention, TBR = Time-Based Retention)
#
# The API key is created at partner level and sees every client unless it is restricted to one organization
# (Access Controls > Select Organization). A body with domains from more than one organizationId is refused:
# the evidence would mix companies.

import json


def transform(input):
    """
    Returns backupSuccessRatePercentage = services with a recent backup / active services x 100, summed over every
    protected domain of the organization (Datto's own backupStats; with one domain this equals its backupPercentage).

    Proves: Datto's backup statistics for every domain the key sees. Does not prove: the length of Datto's "recent"
    window (not documented; the Datto RMM integration labels the same figure "Backup Success Rate (24 hrs)").
    None when a domain carries no usable backupStats or there are no active services.
    """
    key = "backupSuccessRatePercentage"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
        return value

    def read_domains(input):
        """(domains, None) or (None, reason). domains is the documented array of domain objects."""
        data = parse_input(input)
        for depth in range(4):
            if isinstance(data, list):
                break
            if not isinstance(data, dict):
                return None, "Response is not a JSON array or object"
            if data.get("error") or data.get("errors"):
                return None, "Integration-Service or Datto returned an error envelope"
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result", "data", "items"]:
                if wrapper in data and (isinstance(data[wrapper], list) or isinstance(data[wrapper], dict)):
                    data = data[wrapper]
                    moved = True
                    break
            if not moved:
                return None, "Response carries no /v1/saas/domains array"
        if not isinstance(data, list):
            return None, "Response carries no /v1/saas/domains array"
        domains = [d for d in data if isinstance(d, dict) and "saasCustomerId" in d]
        if len(domains) != len(data):
            return None, "Array holds entries that are not SaaS Protection domains"
        if len(domains) == 0:
            return None, "The key sees no SaaS Protection domain"
        orgs = []
        for d in domains:
            org = d.get("organizationId")
            if org not in orgs:
                orgs.append(org)
        if len(orgs) > 1:
            return None, "The key sees " + str(len(orgs)) + " organizations; restrict it to this company's organization"
        return domains, None

    def number(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int) or isinstance(value, float):
            return value
        if isinstance(value, str):
            try:
                return float(value)
            except ValueError:
                return None
        return None

    def stats(d):
        s = d.get("backupStats")
        if not isinstance(s, dict):
            return None, None
        return number(s.get("activeServicesCount")), number(s.get("activeServicesWithRecentBackupCount"))

    try:
        domains, problem = read_domains(input)
        if domains is None:
            return {key: None, "reason": problem}
        active = 0
        recent = 0
        for d in domains:
            a, r = stats(d)
            if a is None or r is None or a < 0 or r < 0 or r > a:
                return {key: None, "reason": "Domain " + str(d.get("domain")) + " has no usable backupStats"}
            active = active + a
            recent = recent + r
        if active == 0:
            return {key: None, "reason": "No active service is protected, so there is no rate to report"}
        rate = round(recent * 100.0 / active, 2)
        return {key: rate, "reason": str(int(recent)) + " of " + str(int(active)) + " active services across " + str(len(domains)) + " domains have a recent backup",
                "activeServices": active, "servicesWithRecentBackup": recent}
    except Exception as e:
        return {key: None, "error": str(e)}
