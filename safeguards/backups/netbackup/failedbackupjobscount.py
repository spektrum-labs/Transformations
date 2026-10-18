# failedbackupjobscount.py - NetBackup (Cohesity NetBackup, formerly Veritas NetBackup)
#
# Method: listBackupJobs
#         GET {serverUrl}/netbackup/admin/jobs?filter=jobType eq 'BACKUP' and state eq 'DONE'&sort=-endTime&page[limit]=100
#         (data[].attributes {jobId, jobType, state, status, startTime, endTime, policyName, clientName};
#         meta.pagination.next when more pages exist). Status 0 = success, 1 = partial success, >1 = failed.
# Spec:   NetBackup REST API reference (https://sort.veritas.com/public/documents/nbu/11.0/windowsandunix/productguides/html/getting-started/)
# Auth:   NetBackup API key in the Authorization header; it acts with the RBAC roles of the user it belongs to.

import json
from datetime import datetime, timezone, timedelta

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('failedBackupJobsCount',)


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
    Returns failedBackupJobsCount = the number of finished BACKUP jobs in the last 7 days whose status is above 1
    (0 is success, 1 partial success). None when the 7 days do not fit in the 100 most recent finished backup jobs
    (the page would undercount), no backup job finished in 7 days, or the body is unreadable.
    """
    key = "failedBackupJobsCount"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
        return value

    def jsonapi(input, want_list):
        """The JSON:API document (with IS wrappers removed); (doc, None) or (None, reason)."""
        data = parse_input(input)
        for depth in range(4):
            if not isinstance(data, dict):
                return None, "Response is not an object"
            if data.get("error") or data.get("errors") or data.get("errorCode"):
                return None, "Integration-Service or NetBackup returned an error envelope"
            inner = data.get("data")
            if want_list and isinstance(inner, list):
                return data, None
            if not want_list and isinstance(inner, dict) and isinstance(inner.get("attributes"), dict):
                return data, None
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result"]:
                if isinstance(data.get(wrapper), dict):
                    data = data[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return None, "Response is not the expected NetBackup JSON:API document"

    try:
        doc, problem = jsonapi(input, True)
        if doc is None:
            return {key: None, "reason": problem}
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        recent = []
        oldest = None
        for item in doc.get("data"):
            att = item.get("attributes") if isinstance(item, dict) else None
            if not isinstance(att, dict):
                return {key: None, "reason": "A job record has no attributes"}
            if str(att.get("jobType") or "").upper() != "BACKUP" or str(att.get("state") or "").upper() != "DONE":
                continue
            end = att.get("endTime")
            status = att.get("status")
            if not isinstance(end, str) or not isinstance(status, int) or isinstance(status, bool):
                return {key: None, "reason": "Job " + str(att.get("jobId")) + " has no endTime or status"}
            when = datetime.fromisoformat(end.replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if oldest is None or when < oldest:
                oldest = when
            if when >= cutoff:
                recent.append(att)
        meta = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
        pag = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
        truncated = bool(pag.get("next")) and oldest is not None and oldest >= cutoff

        if truncated:
            return {key: None, "reason": "More than 100 backup jobs finished in 7 days; the count would be incomplete"}
        if not recent:
            return {key: None, "reason": "No backup job finished in the last 7 days"}
        failed = [a for a in recent if a.get("status") > 1]
        return {key: len(failed), "reason": str(len(failed)) + " of " + str(len(recent)) + " backup jobs finished in 7 days failed (status > 1)",
                "failedJobs": [{"jobId": a.get("jobId"), "status": a.get("status"), "policyName": a.get("policyName"), "clientName": a.get("clientName")} for a in failed[:25]]}
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
