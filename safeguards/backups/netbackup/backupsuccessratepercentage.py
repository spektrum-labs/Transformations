# backupsuccessratepercentage.py - NetBackup (Cohesity NetBackup, formerly Veritas NetBackup)
#
# Method: listBackupJobs
#         GET {serverUrl}/netbackup/admin/jobs?filter=jobType eq 'BACKUP' and state eq 'DONE'&sort=-endTime&page[limit]=100
#         (data[].attributes {jobId, jobType, state, status, startTime, endTime, policyName, clientName};
#         meta.pagination.next when more pages exist). Status 0 = success, 1 = partial success, >1 = failed.
# Spec:   NetBackup REST API reference (https://sort.veritas.com/public/documents/nbu/11.0/windowsandunix/productguides/html/getting-started/)
# Auth:   NetBackup API key in the Authorization header; it acts with the RBAC roles of the user it belongs to.

import json
from datetime import datetime, timezone, timedelta


def transform(input):
    """
    Returns backupSuccessRatePercentage = BACKUP jobs with status 0 / finished BACKUP jobs x 100, over jobs that
    finished in the last 7 days among the 100 most recent (a sample when more than 100 finished). Partial success
    (status 1) is not counted as success. None when no backup job finished in 7 days or the body is unreadable.
    """
    key = "backupSuccessRatePercentage"

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

        if not recent:
            return {key: None, "reason": "No backup job finished in the last 7 days"}
        ok = len([a for a in recent if a.get("status") == 0])
        out = {key: round(ok * 100.0 / len(recent), 2), "reason": str(ok) + " of " + str(len(recent)) + " backup jobs finished in 7 days succeeded (status 0)"}
        if truncated:
            out["reason"] = out["reason"] + " (the 100 most recent; more finished in the window)"
        return out
    except Exception as e:
        return {key: None, "error": str(e)}
