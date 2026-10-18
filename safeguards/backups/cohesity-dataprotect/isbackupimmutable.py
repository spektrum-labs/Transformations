# isbackupimmutable.py - Cohesity DataProtect (Helios / Cohesity Data Cloud)
#
# Method: getProtectionPosture (workflow: getProtectionGroups then getProtectionPolicies, merged)
#         listClusters: GET {serverUrl}/v2/mcm/cluster-mgmt/info (cohesityClusters[].clusterId / clusterName /
#         isConnectedToHelios), then per cluster, routed by the accessClusterId header,
#         GET {serverUrl}/v2/data-protect/protection-groups?includeLastRunInfo=true&isDeleted=false,
#         merged as clusterGroups[] (one body per cluster, an error record for a cluster Helios cannot reach)
#         (protectionGroups[].isActive / isPaused / isDeleted / policyId / lastRun.localBackupInfo
#         {status, isSlaViolated, startTimeUsecs, endTimeUsecs}; paginationCookie when more pages exist)
#         then GET {serverUrl}/v2/mcm/data-protect/policies (policies[].id / backupPolicy.regular
#         {incremental.schedule, full.schedule, retention.dataLockConfig {mode, duration, unit}}), merged
# Schema: Cohesity Helios v2 OpenAPI, https://developer.cohesity.com/apidocs/helios/v2-api/
# Auth:   header apiKey (a Helios API key; it acts with the roles of the user it belongs to).

import json
from datetime import datetime, timezone

VENDOR = "Cohesity"
PRODUCT = "DataProtect"
METHOD = "getProtectionPosture"


def respond(key, value, reason, extra=None):
    """The full response envelope. dataCollection.status is derived from the value, never from a key list:
    None means the body could not answer the check (not measured, "error"); True or False was measured."""
    result = {key: value, "reason": reason}
    if extra:
        for k in extra:
            result[k] = extra[k]
    measured = value is not None
    passed = value is True
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "success" if measured else "error", "errors": [] if measured else [reason]},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": {}},
            "evaluation": {"passReasons": [reason] if passed else [], "failReasons": [] if passed else [reason],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": VENDOR, "product": PRODUCT, "method": METHOD,
                         "category": "backups", "evaluatedAt": datetime.now(timezone.utc).isoformat(),
                         "schemaVersion": "2.0"},
        },
    }


def transform(input):
    """
    Returns isBackupImmutable = True when every policy used by an active protection group locks its regular backups
    (backupPolicy.regular.retention.dataLockConfig with mode Compliance or Administrative and a positive duration:
    DataLock WORM). False when any in-use policy has no lock, or on any unreadable body.
    """
    key = "isBackupImmutable"

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

    def groups_body(input, extra):
        """The protection-group body in either shape Integration-Service sends, as (body, partial, problem).

        Helios' tenant-wide list never carries a group's last run, so the definition lists the clusters
        registered in Helios (clusters.cohesityClusters) and fans the per-cluster list out over them: one
        body per cluster under clusterGroups, in the clusters' order, with an error record in the slot of
        a cluster Helios could not reach (continueOnItemError). The older tenant-wide shape, one list
        under protectionGroups, is still read as before.

        body carries every group read under protectionGroups (each tagged with its clusterName) plus the
        extra markers (policies). partial names what could not be read: a connected cluster whose read
        failed, a cluster whose list was cut short, or clusters beyond the fan-out cap. A cluster that
        Helios reports as not connected is not readable through Helios at all; it is listed under
        clustersNotConnected and does not make the read partial. Slots are matched to clusters by the id an
        error record echoes or the id prefix of the slot's group ids, position only as a last resort; a slot
        count that differs from the cluster count is partial. problem is set when nothing was read at all.
        """
        body, problem = body_with(input, ["clusterGroups"] + extra)
        if body is None:
            legacy, legacy_problem = body_with(input, ["protectionGroups"] + extra)
            if legacy is None:
                return None, None, legacy_problem
            return legacy, None, None
        slots = body.get("clusterGroups")
        if not isinstance(slots, list):
            return None, None, "clusterGroups has an unexpected shape"
        clusters = body.get("clusters")
        known = clusters.get("cohesityClusters") if isinstance(clusters, dict) else None
        if not isinstance(known, list):
            known = []
        by_id = {}
        for c in known:
            if isinstance(c, dict) and c.get("clusterId") is not None:
                by_id[str(c.get("clusterId"))] = c

        def slot_cluster(index, slot):
            """The cluster a slot came from: the cluster id an error record echoes (Integration-Service's
            continueOnItemError record carries the iterate parameter's value under "item", here the
            clusterId), else the id prefix of its group ids (<clusterId>:<incarnation>:<n>), else the
            cluster at the same position."""
            cid = None
            if isinstance(slot, dict) and slot.get("error") is True:
                cid = slot.get("item")
            elif isinstance(slot, dict) and isinstance(slot.get("protectionGroups"), list):
                for g in slot["protectionGroups"]:
                    if isinstance(g, dict) and ":" in str(g.get("id") or ""):
                        cid = str(g.get("id")).split(":")[0]
                        break
            if cid is not None and str(cid) in by_id:
                return by_id[str(cid)]
            return known[index] if index < len(known) and isinstance(known[index], dict) else {}

        groups = []
        unreadable = []
        not_connected = []
        no_runs = []
        read_any = False
        for index, slot in enumerate(slots):
            meta = slot_cluster(index, slot)
            label = str(meta.get("clusterName") or meta.get("clusterId") or "cluster " + str(index + 1))
            if isinstance(slot, dict) and slot.get("error") is True:
                if meta.get("isConnectedToHelios") is False:
                    not_connected.append(label)
                else:
                    unreadable.append(label + " (HTTP " + str(slot.get("statusCode")) + ")")
                continue
            if not isinstance(slot, dict) or not isinstance(slot.get("protectionGroups"), list):
                unreadable.append(label + " (no protection group list)")
                continue
            if slot.get("paginationCookie"):
                unreadable.append(label + " (first page only)")
                continue
            read_any = True
            slot_groups = [g for g in slot["protectionGroups"] if isinstance(g, dict)]
            live_here = [g for g in slot_groups
                         if not (g.get("isDeleted") is True or g.get("isActive") is False or g.get("isPaused") is True)]
            if live_here and not any("lastRun" in g for g in live_here):
                # This cluster answered with live groups but no last-run information on any of them:
                # either it did not honour includeLastRunInfo (or runs a build that does not return
                # it), or none of its groups has run yet. The run checks cannot tell which, so they do
                # not judge it, and must not read its groups as "never ran". Deleted, paused and
                # inactive groups are not judged anyway, so a cluster with only those is not flagged.
                no_runs.append(label)
            for g in slot_groups:
                g = dict(g)
                g["clusterName"] = label
                groups.append(g)
        stats = body.get("iterateStats")
        stats = stats.get("clusterGroups") if isinstance(stats, dict) else None
        if body.get("iterateTruncated") is True or (isinstance(stats, dict) and stats.get("iterateTruncated") is True):
            unreadable.append("clusters beyond the fan-out cap")
        if len(known) > 0 and len(slots) != len(known):
            unreadable.append(str(len(slots)) + " of " + str(len(known)) + " clusters answered")
        if not read_any:
            # Nothing was read: not one cluster list came back. Whether every cluster is disconnected from
            # Helios, every read failed, or the account sees no cluster at all, there is no evidence either
            # way, so the check is not evaluated, never Failed.
            if not_connected and not unreadable:
                return None, None, "No cluster could be read: not connected to Helios: " + ", ".join(not_connected)
            if unreadable:
                return None, None, "No cluster could be read: " + ", ".join(unreadable + not_connected)
            return None, None, "No cluster list was returned (clusterGroups is empty)"
        merged = dict(body)
        merged["protectionGroups"] = groups
        merged["clustersNotConnected"] = not_connected
        merged["clustersWithoutRuns"] = no_runs
        partial = ("Not read: " + ", ".join(unreadable)) if unreadable else None
        return merged, partial, None

    try:
        body, partial, problem = groups_body(input, ["policies"])
        if body is None:
            return respond(key, None, problem)
        live, problem = groups_in(body)
        if live is None:
            return respond(key, None, problem)
        pols = body.get("policies")
        if not isinstance(pols, list):
            return respond(key, None, "policies has an unexpected shape")
        by_id = {}
        for p in pols:
            if isinstance(p, dict) and p.get("id") is not None:
                by_id[str(p.get("id"))] = p
        used = []
        for g in live:
            pid = str(g.get("policyId"))
            if pid not in by_id:
                return respond(key, None, "Protection group " + str(g.get("name")) + " uses policy " + pid + ", which was not returned")
            if by_id[pid] not in used:
                used.append(by_id[pid])
        if not used:
            if partial:
                return respond(key, None, partial + "; no protection group was read, so no policy can be judged")
            skipped = body.get("clustersNotConnected") or []
            skipped_note = ("; not connected to Helios, so not read: " + ", ".join(skipped)) if skipped else ""
            return respond(key, False, "No active protection group, so no policy is in use" + skipped_note)

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
            if lock(p) not in ["Compliance", "Administrative"]:
                return respond(key, False, "Policy " + str(p.get("name")) + " has no DataLock on its regular backups")
        if partial:
            return respond(key, None, partial + "; the policies in use on those clusters could not be judged")
        skipped = body.get("clustersNotConnected") or []
        if skipped:
            # Every policy read is compliant, but a registered cluster was never read: the estate cannot
            # be shown compliant, so this is not evaluated rather than True (a proven False above stands).
            return respond(key, None, "All " + str(len(used)) + " in-use policies on the clusters read are compliant, but not connected to Helios, so not read: " + ", ".join(skipped) + "; the whole estate cannot be shown compliant")

        return respond(key, True, "All " + str(len(used)) + " in-use policies apply DataLock to regular backups")
    except Exception as e:
        return respond(key, None, "Transformation error: " + str(e)[:300], {"error": str(e)[:300]})
