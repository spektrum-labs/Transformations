# isprotectionpolicyrpowithinsla.py - Commvault (Command Center REST API, webconsole/commandcenter api)
#
# Method: getPlanSummary -> GET {serverUrl}/V4/Plan/Summary (Accept: application/json)
# Docs:   https://github.com/Commvault/CVPowershellSDKV2/blob/main/OpenAPI3.yaml (Commvault's published V4 OpenAPI 3 spec)
#         operation GetPlanSummary: plans[].planType (Server, Laptop, Office365, ...), status (ENABLED, DISABLED,
#         INCOMPLETE, HIDDEN, BACKUP_DISABLED), associatedEntities, RPO ("RPO in minutes for the plan"); plansCount.
#
# Every method sends Accept: application/json and authenticates with the Login token in the Authtoken header.

import json


def transform(input):
    """
    isProtectionPolicyRPOWithinSLA = true when every server plan with associated entities is ENABLED and its
    RPO is at most 1440 minutes (24 hours). The 24-hour line is Spektrum's reading of "within SLA"; the
    bundle carries no RPO value. false on an unreadable body or when no server plan is in use.
    """
    key = "isProtectionPolicyRPOWithinSLA"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("<"):
                raise ValueError("XML body; the method must send Accept: application/json")
            return json.loads(text)
        return value

    def unwrap(value, marker):
        # Integration-Service may hand the body back under one of its envelopes.
        for depth in range(3):
            if not isinstance(value, dict) or marker in value:
                break
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(value.get(wrapper), dict):
                    value = value[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return value

    def vendor_error(d):
        """A reason string when the body is an Integration-Service or Commvault error, else None.
        Commvault answers some failures with HTTP 200 and errorCode/errorMessage or errList."""
        if not isinstance(d, dict):
            return "Response is not an object"
        if d.get("error") is True:
            return "Integration-Service returned an error envelope"
        code = d.get("errorCode")
        if code not in (None, 0, "0"):
            return "Commvault error " + str(code) + ": " + str(d.get("errorMessage") or "")
        errs = d.get("errList")
        if isinstance(errs, list) and len(errs) > 0:
            return "Commvault errList: " + str(errs[0])[:200]
        err = d.get("error")
        if isinstance(err, dict) and err.get("errorCode") not in (None, 0, "0"):
            return "Commvault error " + str(err.get("errorCode")) + ": " + str(err.get("errorString") or err.get("errorMessage") or "")
        return None

    def as_int(value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip().lstrip("-").isdigit():
            return int(value.strip())
        return None

    def server_plans(input):
        data = unwrap(parse_input(input), "plans")
        problem = vendor_error(data)
        if problem:
            return None, problem
        plans = data.get("plans")
        if not isinstance(plans, list):
            return None, "Response has no plans list"
        count = as_int(data.get("plansCount"))
        if count is not None and count > len(plans):
            return None, "Read " + str(len(plans)) + " of " + str(count) + " plans"
        used = []
        for p in plans:
            if not isinstance(p, dict):
                return None, "A plan entry is not an object"
            if str(p.get("planType") or "").lower() != "server":
                continue
            if (as_int(p.get("associatedEntities")) or 0) > 0:
                used.append(p)
        return used, None

    def pname(p):
        plan = p.get("plan") if isinstance(p.get("plan"), dict) else {}
        return str(plan.get("name") or plan.get("id") or "?")

    try:
        used, problem = server_plans(input)
        if used is None:
            return {key: False, "reason": problem}
        if len(used) == 0:
            return {key: False, "reason": "No server plan has associated entities"}
        limit = 1440
        bad = []
        for p in used:
            rpo = as_int(p.get("RPO"))
            if str(p.get("status") or "").upper() != "ENABLED" or rpo is None or rpo <= 0 or rpo > limit:
                bad.append(pname(p) + " (status " + str(p.get("status")) + ", RPO " + str(p.get("RPO")) + " min)")
        if bad:
            return {key: False, "reason": str(len(bad)) + " of " + str(len(used)) + " server plans in use have no RPO or one above 1440 minutes", "plans": bad[:25]}
        return {key: True, "reason": "All " + str(len(used)) + " server plans in use have an RPO of 1440 minutes or less"}
    except Exception as e:
        return {key: False, "error": str(e)}
