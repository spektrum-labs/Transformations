# confirmedlicensepurchased.py - Datto SaaS Protection (Kaseya)
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
    Returns confirmedLicensePurchased = True when every protected domain of the organization carries a SaaS
    Protection subscription (externalSubscriptionId) and at least one used seat (seatsUsed > 0).

    Proves: a SaaS Protection subscription with licensed seats exists for each domain. Does not prove: the number
    of seats purchased (the API documents only seatsUsed). False on any unreadable body.
    """
    key = "confirmedLicensePurchased"

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
            return {key: False, "reason": problem}
        for d in domains:
            sub = d.get("externalSubscriptionId")
            seats = number(d.get("seatsUsed"))
            if not isinstance(sub, str) or not sub.strip():
                return {key: False, "reason": "Domain " + str(d.get("domain")) + " carries no externalSubscriptionId"}
            if seats is None or seats <= 0:
                return {key: False, "reason": "Domain " + str(d.get("domain")) + " has no used seats"}
        return {key: True, "reason": "All " + str(len(domains)) + " protected domains carry a subscription with used seats"}
    except Exception as e:
        return {key: False, "error": str(e)}
