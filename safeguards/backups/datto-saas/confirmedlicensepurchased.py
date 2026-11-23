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
from datetime import datetime, timezone

KEY = "confirmedLicensePurchased"


def transform_bare(input):
    """
    Returns confirmedLicensePurchased = True when every protected domain of the organization carries a SaaS
    Protection subscription (externalSubscriptionId) and at least one used seat (seatsUsed > 0).

    Proves: a SaaS Protection subscription with licensed seats exists for each domain. Does not prove: the number
    of seats purchased (the API documents only seatsUsed). False when a domain's subscription id is blank or
    it uses no seats; None (not measured) on an unreadable body or a domain missing either field.
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
            return {key: None, "reason": problem}
        failed = []
        unread = []
        for d in domains:
            sub = d.get("externalSubscriptionId")
            seats = number(d.get("seatsUsed"))
            if not isinstance(sub, str):
                unread.append("Domain " + str(d.get("domain")) + " carries no externalSubscriptionId field")
            elif not sub.strip():
                failed.append("Domain " + str(d.get("domain")) + " carries no externalSubscriptionId")
            if seats is None:
                unread.append("Domain " + str(d.get("domain")) + " carries no readable seatsUsed")
            elif seats <= 0:
                failed.append("Domain " + str(d.get("domain")) + " has no used seats")
        if failed:
            return {key: False, "reason": "; ".join(failed + unread)}
        if unread:
            return {key: None, "reason": "; ".join(unread)}
        return {key: True, "reason": "All " + str(len(domains)) + " protected domains carry a subscription with used seats"}
    except Exception as e:
        return {key: None, "error": str(e)}


def envelope(key, bare):
    """Wrap a bare result in the platform envelope.

    Whether the criterion was measured is read from its value alone: None means the body could
    not answer the check, so dataCollection reports an error and Token-Service does not grade
    it. Every other value, including a measured False, reports success.
    """
    value = bare.get(key)
    reason = str(bare.get("reason") or bare.get("error") or "The response could not answer this check")
    measured = value is not None
    passed = value is True
    return {
        "transformedResponse": bare,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [], "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": "Datto", "product": "SaaS Protection",
                         "method": "getSaasDomains", "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                         "schemaVersion": "2.0"},
        },
    }


def transform(input):
    """transform_bare() in the platform envelope; a None criterion reports a dataCollection error."""
    return envelope(KEY, transform_bare(input))
