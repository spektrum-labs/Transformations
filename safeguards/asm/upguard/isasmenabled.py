# isasmenabled.py - UpGuard (Attack Surface Management, c2104db1)
#
# Method: getActiveDomains -> GET https://cyber-risk.upguard.com/api/public/domains?active=true
#         (page_token / next_page_token, all pages)
# Docs:   https://cyber-risk.upguard.com/api/docs (spec /api/swagger.json)
#           GET /domains "Returns a list of domains for your account."; Domain.active "The status of
#           the domain"; Domain.scanned_at "The time the domain was scanned. If the domain is inactive
#           or hasn't been scanned yet this field will be absent". Permission: BreachRisk

import json


def transform(input):
    """
    True when at least one domain is active and has been scanned: UpGuard is monitoring the
    organisation's external surface. False on an empty list, unscanned domains, or any unreadable body.
    """
    key = "isASMEnabled"

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    def unwrap(value, marker):
        for depth in range(4):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for w in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(w), dict):
                    value = value[w]
                    moved = True
                    break
            if not moved:
                break
        return value

    try:
        data = unwrap(parse(input), "domains")
        if not isinstance(data, dict) or not isinstance(data.get("domains"), list):
            return {key: False, "reason": "Response has no domains list (the /domains call did not run)"}
        scanned = [d for d in data["domains"] if isinstance(d, dict) and d.get("active") is True and d.get("scanned_at")]
        if scanned:
            return {key: True, "reason": "Active domains are being scanned", "scannedDomains": len(scanned), "domainCount": len(data["domains"])}
        return {key: False, "reason": "No active domain has been scanned", "domainCount": len(data["domains"])}
    except Exception as e:
        return {key: False, "error": str(e)}
