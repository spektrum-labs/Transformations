# failedbackupjobscount.py - Cohesity DataProtect (Helios / Cohesity Data Cloud)
#
# Method: getProtectionGroups
#         GET {serverUrl}/v2/mcm/data-protect/protection-groups?includeLastRunInfo=true
#         (protectionGroups[].isActive / isPaused / isDeleted / policyId / lastRun.localBackupInfo
#         {status, isSlaViolated, startTimeUsecs, endTimeUsecs}; paginationCookie when more pages exist)
# Schema: Cohesity Helios v2 OpenAPI, https://developer.cohesity.com/apidocs/helios/v2-api/
# Auth:   header apiKey (a Helios API key; it acts with the roles of the user it belongs to).

import json
from datetime import datetime, timezone


def transform(input):
    """
    Returns failedBackupJobsCount = the number of active protection groups whose LAST run's local backup ended Failed
    (Cohesity keeps one last-run record per group; earlier runs are not read). None when a group has no last-run
    record, the list is incomplete (paginationCookie) or the body is unreadable, so a broken read never reports zero.
    """
    key = "failedBackupJobsCount"

    def parse_input(value):
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        if isinstance(value, str):
            return json.loads(value)
        return value

    def body_with(input, markers):
        """The response object holding every marker key, with IS wrappers removed; (body, None) or (None, reason)."""
        data = parse_input(input)
        for depth in range(4):
            if not isinstance(data, dict):
                return None, "Response is not an object"
            if data.get("error") or data.get("errors") or data.get("errorCode"):
                return None, "Integration-Service or Helios returned an error envelope"
            if all([m in data for m in markers]):
                return data, None
            moved = False
            for wrapper in ["apiResponse", "_response_data", "response", "result", "data"]:
                if isinstance(data.get(wrapper), dict):
                    data = data[wrapper]
                    moved = True
                    break
            if not moved:
                break
        return None, "Response carries no " + " / ".join(markers)

    def groups_in(body):
        """Active, not paused, not deleted protection groups; (groups, None) or (None, reason)."""
        pgs = body.get("protectionGroups")
        if pgs is None:
            pgs = []
        if not isinstance(pgs, list):
            return None, "protectionGroups has an unexpected shape"
        if body.get("paginationCookie"):
            return None, "Helios returned only the first page of protection groups"
        live = []
        for g in pgs:
            if not isinstance(g, dict):
                return None, "protectionGroups holds a non-object"
            if g.get("isDeleted") is True or g.get("isActive") is False or g.get("isPaused") is True:
                continue
            live.append(g)
        return live, None

    def last_backup(g):
        run = g.get("lastRun")
        if not isinstance(run, dict):
            return None
        info = run.get("localBackupInfo")
        if not isinstance(info, dict):
            return None
        return info

    try:
        body, problem = body_with(input, ["protectionGroups"])
        if body is None:
            return {key: None, "reason": problem}
        live, problem = groups_in(body)
        if live is None:
            return {key: None, "reason": problem}
        if not live:
            return {key: None, "reason": "No active protection group, so there are no backup runs to count"}
        failed = []
        for g in live:
            info = last_backup(g)
            if info is None or not info.get("status"):
                return {key: None, "reason": "Protection group " + str(g.get("name")) + " has no last-run record (was includeLastRunInfo sent?)"}
            if info.get("status") == "Failed":
                failed.append(str(g.get("name")))
        return {key: len(failed), "reason": str(len(failed)) + " of " + str(len(live)) + " active protection groups ended their last backup run Failed", "failedGroups": failed[:50]}
    except Exception as e:
        return {key: None, "error": str(e)}
