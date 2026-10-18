# pendingapprovalrequestcount.py - ThreatLocker (Endpoint Security, 69b438a1)
#
# Method: getPendingApprovalCount -> GET {serverUrl}/portalapi/ApprovalRequest/ApprovalRequestGetCount
#         ?includeChildOrganizations=true
# Docs:   https://threatlocker.kb.help/portalapiapprovalrequest/ (ApprovalRequestGetCount)
#           "this API will only get the count of Approval Requests with a status of "Pending" and
#           return it as an Integer". Approval Requests cover Application Control, Elevation Control
#           and Storage Control. Permission: View Approvals

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('pendingApprovalRequestCount',)


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
    The number of Pending approval requests ThreatLocker reports for the organization (and its
    child organizations). None when the body is not a non-negative integer.
    """
    key = "pendingApprovalRequestCount"

    def parse(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            value = json.loads(value) if value.strip() else None
        return value

    try:
        data = parse(input)
        for depth in range(4):
            if not isinstance(data, dict):
                break
            moved = False
            for w in ["apiResponse", "_response_data", "response", "result"]:
                if w in data:
                    data = parse(data[w])
                    moved = True
                    break
            if not moved:
                break
        if isinstance(data, bool) or not isinstance(data, int) or data < 0:
            return {key: None, "reason": "Response is not the documented integer count"}
        return {key: data}
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
