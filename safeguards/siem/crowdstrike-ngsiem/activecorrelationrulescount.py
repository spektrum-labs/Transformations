# activecorrelationrulescount.py - CrowdStrike Falcon Next-Gen SIEM (Security Operations, 1e1212b3)
#
# Method: getActiveCorrelationRules -> GET {serverUrl}/correlation-rules/combined/rules/v1
#         ?filter=status:'active'&limit=500
# Docs:   CrowdStrike API, Correlation Rules collection (combined_rules_get_v1): "Find all rules matching
#         the query and filter. Supported filters: customer_id,user_id,user_uuid,status,name,...";
#         MSA envelope meta.pagination.total, resources[], errors[]. Rule status "active" enables the rule,
#         "inactive" disables it (CrowdStrike correlation_rule module docs). Scope: Correlation Rules: Read.

import json


def transform(input):
    """
    Count of NG-SIEM correlation rules with status "active" (meta.pagination.total of the filtered query). None when unreadable.
    The server filters on status; every returned rule must also say "active", or the answer is refused.
    """
    key = "activeCorrelationRulesCount"

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    def unwrap(value):
        for depth in range(4):
            if not isinstance(value, dict) or "resources" in value:
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
        data = unwrap(parse(input))
        if not isinstance(data, dict) or not isinstance(data.get("meta"), dict) or not isinstance(data.get("resources", []), list):
            return {key: None, "reason": "Response is not a CrowdStrike MSA body"}
        if data.get("errors"):
            return {key: None, "reason": "CrowdStrike returned errors", "errors": data.get("errors")}
        rules = data.get("resources") or []
        for r in rules:
            if not isinstance(r, dict) or str(r.get("status") or "").lower() != "active":
                return {key: None, "reason": "A returned rule is not active: the status filter was not applied"}
        pagination = data["meta"].get("pagination")
        n = pagination.get("total") if isinstance(pagination, dict) else None
        if isinstance(n, bool) or not isinstance(n, int) or n < len(rules):
            return {key: None, "reason": "meta.pagination.total is missing or smaller than the rules returned"}
        return {key: n, "activeRules": n}
    except Exception as e:
        return {key: None, "error": str(e)}
