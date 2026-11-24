# requiredcoveragepercentage.py - Palo Alto Networks Cortex XDR (Endpoint Security, f1b50389)
#
# Method: getEndpointCounts (IS workflow). Each step POSTs {serverUrl}/public_api/v1/endpoints/get_endpoint
#         with one filter and stores the body under its output key:
#           enrolled  = endpoint_status in [connected, disconnected, lost]
#           connected = endpoint_status in [connected]
#           offline   = endpoint_status in [disconnected, lost]
#           isolated  = isolate in [isolated]
# Docs:   Cortex XDR REST API, Get Endpoint (docs-cortex.paloaltonetworks.com/r/Cortex-XDR-REST-API/Get-Endpoint):
#           response reply.total_count / result_count / endpoints; endpoint_status CONNECTED, DISCONNECTED,
#           LOST, UNINSTALLED; is_isolated AGENT_ISOLATED / AGENT_PENDING_ISOLATION / AGENT_UNISOLATED.
#         The server counts (total_count), so no endpoint paging is needed.
#
# Coverage is enrolled endpoints that are not LOST (CONNECTED + DISCONNECTED) over enrolled endpoints.
# CONNECTED alone measured how many endpoints were online when the check ran: a run at night, with
# laptops asleep or shut down, read 12-14 points lower than the same fleet in the afternoon. A
# DISCONNECTED endpoint still has the agent installed and protecting it; only a LOST one has dropped
# out of contact long enough that its protection cannot be shown.
#
# The workflow has no step that separates DISCONNECTED from LOST (offline is both), so the LOST
# count is taken, in order, from: a `lost` step (endpoint_status in [lost]); a `disconnected` step
# (lost = offline - disconnected); or the offline step's own endpoint list, when it holds every
# offline endpoint (result_count == total_count) and each one carries a readable endpoint_status.
# offline == 0 means nothing is LOST. When none of these can show the LOST count, the score falls
# back to CONNECTED / enrolled (the old reading) and says so in coverageBasis and finding; adding a
# `lost` step to the Integration-Service workflow removes that fallback.

import json

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('requiredCoveragePercentage',)


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
    Enrolled endpoints that are not LOST / enrolled endpoints (CONNECTED + DISCONNECTED + LOST) x 100,
    to 2 decimals; CONNECTED / enrolled when the LOST count cannot be read (see the header).
    None when either count is unreadable, nothing is enrolled, or the counts are inconsistent.
    """
    key = "requiredCoveragePercentage"

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

    def total(data, name):
        """reply.total_count of the get_endpoint call stored under <name>, or None."""
        body = unwrap(data.get(name), "reply") if isinstance(data, dict) else None
        reply = body.get("reply") if isinstance(body, dict) else None
        if not isinstance(reply, dict):
            return None
        n = reply.get("total_count")
        if isinstance(n, int) and not isinstance(n, bool) and n >= 0:
            return n
        return None

    def listed_lost(data, offline):
        """LOST endpoints counted from the offline step's endpoint list, or None unless it is complete."""
        body = unwrap(data.get("offline"), "reply")
        reply = body.get("reply") if isinstance(body, dict) else None
        endpoints = reply.get("endpoints") if isinstance(reply, dict) else None
        if not isinstance(endpoints, list) or len(endpoints) != offline:
            return None
        lost = 0
        for endpoint in endpoints:
            status = endpoint.get("endpoint_status") if isinstance(endpoint, dict) else None
            status = str(status or "").strip().upper()
            if status == "LOST":
                lost = lost + 1
            elif status != "DISCONNECTED":
                return None
        return lost

    def lost_count(data, offline):
        """(LOST endpoints, how it was read), or (None, None) when the body cannot show it."""
        lost = total(data, "lost")
        if lost is not None:
            return lost, "lost step"
        if offline is None:
            return None, None
        if offline == 0:
            return 0, "no offline endpoints"
        disconnected = total(data, "disconnected")
        if disconnected is not None and disconnected <= offline:
            return offline - disconnected, "offline minus disconnected"
        lost = listed_lost(data, offline)
        if lost is not None:
            return lost, "offline endpoint list"
        return None, None

    try:
        data = unwrap(parse(input), "enrolled")
        if isinstance(data, dict) and (data.get("error") or str(data.get("status", "")).lower() == "error"):
            return {key: None, "reason": "Integration-Service returned an error envelope"}
        enrolled = total(data, "enrolled")
        connected = total(data, "connected")
        if enrolled is None or connected is None:
            return {key: None, "reason": "Enrolled or connected count unreadable"}
        if enrolled == 0 or connected > enrolled:
            return {key: None, "reason": "No enrolled endpoints, or counts inconsistent", "enrolledEndpoints": enrolled, "connectedEndpoints": connected}
        offline = total(data, "offline")
        lost, source = lost_count(data, offline)
        if lost is not None and connected + lost <= enrolled:
            covered = enrolled - lost
            return {key: round(covered * 100.0 / enrolled, 2), "enrolledEndpoints": enrolled,
                    "connectedEndpoints": connected, "coveredEndpoints": covered, "lostEndpoints": lost,
                    "coverageBasis": "notLost",
                    "finding": (str(covered) + " of " + str(enrolled) + " enrolled endpoints are CONNECTED or "
                                "DISCONNECTED (not LOST) and counted as covered; LOST count from the "
                                + source + ".")}
        return {key: round(connected * 100.0 / enrolled, 2), "enrolledEndpoints": enrolled,
                "connectedEndpoints": connected, "coveredEndpoints": connected, "coverageBasis": "connected",
                "finding": ("The LOST endpoint count could not be read (no lost or disconnected step, and the "
                            "offline endpoint list is incomplete), so only CONNECTED endpoints are counted as "
                            "covered. This reading depends on how many endpoints are online when the check runs.")}
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
