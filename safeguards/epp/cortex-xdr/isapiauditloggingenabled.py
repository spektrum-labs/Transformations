# isapiauditloggingenabled.py - Palo Alto Networks Cortex XDR (Endpoint Security, f1b50389)
#
# Method: getManagementLogs -> POST {serverUrl}/public_api/v1/audits/management_logs
#         body {"request_data": {"search_from": 0, "search_to": 1}}
# Docs:   Cortex XDR REST API, Get Audit Management Log: response reply.total_count (not on every tenant),
#         reply.result_count, reply.data (audit records: AUDIT_ID, AUDIT_OWNER_NAME, AUDIT_ENTITY, AUDIT_INSERT_TIME, ...).

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('isApiAuditLoggingEnabled',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


def transform_unmarked(input):
    """
    True when the tenant's management audit log returns at least one record through the API.
    False when the log is readable and holds no record. None on a missing reply or any unreadable body.
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
            return {key: None, "reason": "Response has no reply (the management_logs call did not run)"}
        n = reply.get("total_count")
        if isinstance(n, bool) or not isinstance(n, int):
            rows = reply.get("data")
            n = len(rows) if isinstance(rows, list) else None
        if n is None:
            return {key: None, "reason": "reply has neither total_count nor a data list"}
        if n >= 1:
            return {key: True, "reason": "Management audit log holds %d records" % n, "auditRecords": n}
        return {key: False, "reason": "Management audit log returned no records", "auditRecords": n}
    except Exception as e:
        return {key: None, "error": str(e)}


def transform(input):
    """transform_unmarked(), with a None criterion reported as not evaluated.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". This file's responses do not set that status, so it is set here, carrying the
    file's own reason for the None.
    """
    out = transform_unmarked(input)
    if not isinstance(out, dict):
        return out
    inner = out.get("transformedResponse", out)
    if not isinstance(inner, dict) or not criteria_unmeasured(inner):
        return out
    info = out.get("additionalInfo")
    info = info if isinstance(info, dict) else {}
    collection = info.get("dataCollection")
    if isinstance(collection, dict) and str(collection.get("status") or "").lower() == "error":
        return out
    evaluation = info.get("evaluation")
    reasons = evaluation.get("failReasons") if isinstance(evaluation, dict) else None
    why = [str(r) for r in reasons if r] if isinstance(reasons, list) else []
    for k in ("reason", "error", "unevaluated"):
        if out.get(k) and str(out.get(k)) not in why:
            why = why + [str(out.get(k))]
    errors = collection.get("errors") if isinstance(collection, dict) else None
    why = why + [str(e) for e in errors if e] if isinstance(errors, list) else why
    marked = dict(collection if isinstance(collection, dict) else {}, status="error",
                  errors=why or ["The response could not answer this check, so it was not evaluated."])
    return dict(out, additionalInfo=dict(info, dataCollection=marked))
