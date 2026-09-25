# isdeletionretentionperiodenforced.py - Datto SaaS Protection (Kaseya)
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
    Returns isDeletionRetentionPeriodEnforced = True when every protected domain of the organization uses
    Infinite Cloud Retention (retentionType "ICR"): Datto keeps every backed-up version, deleted items included.

    Proves: retention is infinite for each domain. Does not prove: the period of Time-Based Retention (TBR); the
    API documents no period, so a TBR domain returns None (not evidenced) rather than a pass or a fail.
    """
    key = "isDeletionRetentionPeriodEnforced"

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
        tbr = []
        for d in domains:
            kind = str(d.get("retentionType") or "").strip().upper()
            if kind == "ICR":
                continue
            if kind == "TBR":
                tbr.append(str(d.get("domain")))
                continue
            return {key: False, "reason": "Domain " + str(d.get("domain")) + " has an unrecognised retentionType " + repr(d.get("retentionType"))}
        if tbr:
            return {key: None, "reason": "Time-Based Retention on " + ", ".join(tbr) + "; the API does not expose the retention period"}
        return {key: True, "reason": "All " + str(len(domains)) + " protected domains use Infinite Cloud Retention"}
    except Exception as e:
        return {key: False, "error": str(e)}
