# staleprotectionjobscount.py - Cohesity DataProtect (Helios / Cohesity Data Cloud)
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
    Returns staleProtectionJobsCount = the number of active, unpaused protection groups with no successful backup in
    the last 7 days, judged by the last run: none recorded, not Succeeded/SucceededWithWarning, or started more than 7
    days ago. None when the list is incomplete or the body is unreadable.
    """
    key = "staleProtectionJobsCount"

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
            return {key: None, "reason": "No active protection group"}
        now_us = int(datetime.now(timezone.utc).timestamp() * 1000000)
        limit = now_us - 7 * 24 * 3600 * 1000000
        stale = []
        for g in live:
            info = last_backup(g)
            status = info.get("status") if info is not None else None
            start = info.get("startTimeUsecs") if info is not None else None
            if status not in ["Succeeded", "SucceededWithWarning"] or not isinstance(start, int) or isinstance(start, bool) or start < limit:
                stale.append(str(g.get("name")))
        return {key: len(stale), "reason": str(len(stale)) + " of " + str(len(live)) + " active protection groups have no successful backup in 7 days", "staleGroups": stale[:50]}
    except Exception as e:
        return {key: None, "error": str(e)}
