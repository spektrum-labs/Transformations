# isbackuptypesscheduled.py - Cohesity DataProtect (Helios / Cohesity Data Cloud)
#
# Method: getProtectionPosture (workflow: getProtectionGroups then getProtectionPolicies, merged)
#         GET {serverUrl}/v2/mcm/data-protect/protection-groups?includeLastRunInfo=true
#         (protectionGroups[].isActive / isPaused / isDeleted / policyId / lastRun.localBackupInfo
#         {status, isSlaViolated, startTimeUsecs, endTimeUsecs}; paginationCookie when more pages exist)
#         then GET {serverUrl}/v2/mcm/data-protect/policies (policies[].id / backupPolicy.regular
#         {incremental.schedule, full.schedule, retention.dataLockConfig {mode, duration, unit}}), merged
# Schema: Cohesity Helios v2 OpenAPI, https://developer.cohesity.com/apidocs/helios/v2-api/
# Auth:   header apiKey (a Helios API key; it acts with the roles of the user it belongs to).

import json
from datetime import datetime, timezone


def transform(input):
    """
    Returns isBackupTypesScheduled = True when every policy used by an active protection group schedules regular
    backups: an incremental schedule with a unit, or a full schedule with a unit other than ProtectOnce.
    """
    key = "isBackupTypesScheduled"

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
        body, problem = body_with(input, ["protectionGroups", "policies"])
        if body is None:
            return {key: False, "reason": problem}
        live, problem = groups_in(body)
        if live is None:
            return {key: False, "reason": problem}
        pols = body.get("policies")
        if not isinstance(pols, list):
            return {key: False, "reason": "policies has an unexpected shape"}
        by_id = {}
        for p in pols:
            if isinstance(p, dict) and p.get("id") is not None:
                by_id[str(p.get("id"))] = p
        used = []
        for g in live:
            pid = str(g.get("policyId"))
            if pid not in by_id:
                return {key: False, "reason": "Protection group " + str(g.get("name")) + " uses policy " + pid + ", which was not returned"}
            if by_id[pid] not in used:
                used.append(by_id[pid])
        if not used:
            return {key: False, "reason": "No active protection group, so no policy is in use"}

        def regular(p):
            bp = p.get("backupPolicy")
            if not isinstance(bp, dict) or not isinstance(bp.get("regular"), dict):
                return None
            return bp.get("regular")

        def lock(p):
            reg = regular(p)
            ret = reg.get("retention") if reg is not None else None
            cfg = ret.get("dataLockConfig") if isinstance(ret, dict) else None
            if not isinstance(cfg, dict):
                return None
            dur = cfg.get("duration")
            if not isinstance(dur, int) or isinstance(dur, bool) or dur <= 0:
                return None
            return cfg.get("mode")

        for p in used:
            reg = regular(p)
            ok = False
            if reg is not None:
                inc = reg.get("incremental")
                full = reg.get("full")
                if isinstance(inc, dict) and isinstance(inc.get("schedule"), dict) and inc["schedule"].get("unit"):
                    ok = True
                if isinstance(full, dict) and isinstance(full.get("schedule"), dict) and full["schedule"].get("unit") not in [None, "", "ProtectOnce"]:
                    ok = True
            if not ok:
                return {key: False, "reason": "Policy " + str(p.get("name")) + " has no recurring regular backup schedule"}
        return {key: True, "reason": "All " + str(len(used)) + " in-use policies schedule recurring regular backups"}
    except Exception as e:
        return {key: False, "error": str(e)}
