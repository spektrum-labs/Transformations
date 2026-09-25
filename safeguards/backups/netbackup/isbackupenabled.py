# isbackupenabled.py - NetBackup (Cohesity NetBackup, formerly Veritas NetBackup)
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
    Returns isBackupEnabled = True when at least one BACKUP job finished with status 0 or 1 in the last 7 days.
    False on none, or on any unreadable body.
    """
    key = "isBackupEnabled"

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
            return {key: False, "reason": problem}
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        recent = []
        oldest = None
        for item in doc.get("data"):
            att = item.get("attributes") if isinstance(item, dict) else None
            if not isinstance(att, dict):
                return {key: False, "reason": "A job record has no attributes"}
            if str(att.get("jobType") or "").upper() != "BACKUP" or str(att.get("state") or "").upper() != "DONE":
                continue
            end = att.get("endTime")
            status = att.get("status")
            if not isinstance(end, str) or not isinstance(status, int) or isinstance(status, bool):
                return {key: False, "reason": "Job " + str(att.get("jobId")) + " has no endTime or status"}
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

        ok = [a for a in recent if a.get("status") in [0, 1]]
        if not ok:
            return {key: False, "reason": "No backup job finished successfully in the last 7 days (" + str(len(recent)) + " finished)"}
        return {key: True, "reason": str(len(ok)) + " backup jobs finished successfully in the last 7 days"}
    except Exception as e:
        return {key: False, "error": str(e)}
