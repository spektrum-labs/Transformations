# isapiauditloggingenabled.py - Palo Alto Networks Cortex XDR (Endpoint Security, f1b50389)
#
# Method: getManagementLogs -> POST {serverUrl}/public_api/v1/audits/management_logs
#         body {"request_data": {"search_from": 0, "search_to": 1}}
# Docs:   Cortex XDR REST API, Get Audit Management Log: response reply.total_count (not on every tenant),
#         reply.result_count, reply.data (audit records: AUDIT_ID, AUDIT_OWNER_NAME, AUDIT_ENTITY, AUDIT_INSERT_TIME, ...).

import json


def transform(input):
    """
    True when the tenant's management audit log returns at least one record through the API.
    False on zero records, a missing reply, or any unreadable body.
    """
    key = "isApiAuditLoggingEnabled"

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
        data = unwrap(parse(input), "reply")
        reply = data.get("reply") if isinstance(data, dict) else None
        if not isinstance(reply, dict):
            return {key: False, "reason": "Response has no reply (the management_logs call did not run)"}
        n = reply.get("total_count")
        if isinstance(n, bool) or not isinstance(n, int):
            rows = reply.get("data")
            n = len(rows) if isinstance(rows, list) else None
        if n is None:
            return {key: False, "reason": "reply has neither total_count nor a data list"}
        if n >= 1:
            return {key: True, "reason": "Management audit log holds %d records" % n, "auditRecords": n}
        return {key: False, "reason": "Management audit log returned no records", "auditRecords": n}
    except Exception as e:
        return {key: False, "error": str(e)}
