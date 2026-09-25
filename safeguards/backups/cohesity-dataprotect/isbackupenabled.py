# isbackupenabled.py - Cohesity DataProtect (Helios / Cohesity Data Cloud)
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
    Returns isBackupEnabled = True when at least one protection group is active, not paused and not deleted, and its
    last run's local backup finished Succeeded or SucceededWithWarning. False on any unreadable body.
    """
    key = "isBackupEnabled"

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
            return {key: False, "reason": problem}
        pgs = body.get("protectionGroups")
        if not isinstance(pgs, list):
            return {key: False, "reason": "protectionGroups has an unexpected shape"}
        good = []
        for g in pgs:
            if not isinstance(g, dict) or g.get("isDeleted") is True or g.get("isActive") is False or g.get("isPaused") is True:
                continue
            info = last_backup(g)
            if info is not None and info.get("status") in ["Succeeded", "SucceededWithWarning"]:
                good.append(str(g.get("name")))
        if not good:
            return {key: False, "reason": "No active protection group has a successful last backup run"}
        return {key: True, "reason": str(len(good)) + " active protection groups have a successful last backup run", "groups": good[:20]}
    except Exception as e:
        return {key: False, "error": str(e)}
