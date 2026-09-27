# nocriticalfindings.py - UpGuard (Attack Surface Management, c2104db1)
#
# Method: getRisks -> GET https://cyber-risk.upguard.com/api/public/risks?min_severity=high
# Docs:   https://cyber-risk.upguard.com/api/docs (spec /api/swagger.json)
#           GET /risks "Returns a list of risks that have been detected for your account."
#           min_severity enum info|low|medium|high|critical; Risk.severity "The risk severity"
#           Required API key permission: BreachRisk

import json


def transform(input):
    """
    True when the account's active risk list (severity high and above) holds no risk rated critical.

    Waived risks still count: a waiver is an accepted risk, not a closed one.
    False when the body has no risks list, or any risk carries a severity outside the documented
    enum (it could be critical).
    """
    key = "noCriticalFindings"
    documented = ["info", "low", "medium", "high", "critical"]

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
        data = unwrap(parse(input), "risks")
        if not isinstance(data, dict) or not isinstance(data.get("risks"), list):
            return {key: False, "reason": "Response has no risks list (the /risks call did not run)"}
        hits = 0
        for r in data["risks"]:
            sev = str((r.get("severity") if isinstance(r, dict) else "") or "").strip().lower()
            if sev not in documented:
                return {key: False, "reason": "A risk has an undocumented severity", "severity": sev}
            if sev == "critical":
                hits = hits + 1
        if hits:
            return {key: False, "reason": "Open critical risks detected", "count": hits, "riskCount": len(data["risks"])}
        return {key: True, "reason": "No open critical risks", "riskCount": len(data["risks"])}
    except Exception as e:
        return {key: False, "error": str(e)}
