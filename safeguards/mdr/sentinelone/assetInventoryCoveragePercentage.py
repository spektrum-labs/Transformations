"""Transformation: assetInventoryCoveragePercentage - SentinelOne Vigilance MDR, method getAgents.

Percentage of endpoints known to SentinelOne (every registered agent that has not been
decommissioned, within the check-in window below) that still have the agent installed. Installation
needs positive evidence: isUninstalled explicitly false, or (with no isUninstalled flag) isActive true,
the evidence the earlier version used. An agent with no readable flag (isUninstalled missing or null and
isActive not true) stays in the denominator as NOT covered and is reported as unreadAgentCount; when
more than half of the agents in the window are unreadable the result is None, not a percentage of a
minority. Endpoints SentinelOne has never seen (no agent, no Ranger record in this response) cannot be
counted, so this measures coverage of the SentinelOne-registered inventory. None when the agent list is
missing, an error, or partial, or when every agent is outside the window.

A lastActiveDate more than a day after the time of the read is not a check-in (a clock fault or a
placeholder): it is read as no date, so the agent is judged like any undated agent and the date never
anchors the 15-day window.

It deliberately does NOT gate on isActive, matching epp/sentinelone/requiredCoveragePercentage.py:
isActive reflects only a current console session, so it is false for asleep, offline or roaming
endpoints that remain installed and protected. Gating on it made the score follow how many
endpoints were online when the check ran and produced false low-coverage fails. Staleness is
handled the same way as there: an agent whose lastActiveDate is more than 15 days before the newest
check-in in the response is left out of the count and reported as staleAgentCount. isEDRAgentActive
and staleAgentOfflineCount are the checks about activity.
"""
import json
from datetime import datetime, timedelta

ACTIVE_WINDOW_DAYS = 15


def coerce_bool(value):
    """Real bool from a SentinelOne boolean-ish field (native bool or 'true'/'false')."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return False


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def find_list(obj):
    """(items, pagination, error) from a SentinelOne list response, whatever wrapper Token-Service hands over."""
    cur = obj
    for depth in range(6):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None, None
        if isinstance(cur, list):
            return cur, None, None
        if not isinstance(cur, dict):
            return None, None, None
        if cur.get("errors") or cur.get("error") is True:
            detail = cur.get("errors") or cur.get("message") or cur.get("errorMessage") or "error"
            return None, None, json.dumps(detail)[:300]
        if isinstance(cur.get("data"), list):
            pagination = cur.get("pagination")
            return cur["data"], (pagination if isinstance(pagination, dict) else None), None
        nxt = None
        for key in ["result", "response", "apiResponse", "api_response", "Output", "data"]:
            if isinstance(cur.get(key), (dict, list, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None, None
        cur = nxt
    return None, None, None


def server_total(pagination):
    if pagination is None:
        return None
    total = pagination.get("totalItems")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return None
    return total


def complete_read(raw, noun):
    """(items, None) for a complete paginated read, else (None, problem).

    Complete means: a list with SentinelOne's pagination block, a numeric totalItems, no
    nextCursor left, no IS `truncated` marker, and at least totalItems items. Anything else is a
    partial or unreadable read and is not scored.
    """
    items, pagination, error = find_list(raw)
    if error is not None:
        return None, "SentinelOne returned an error instead of a " + noun + " list: " + error
    if items is None:
        return None, "No SentinelOne " + noun + " list in the response; nothing to evaluate."
    total = server_total(pagination)
    if total is None:
        return None, "The " + noun + " list carries no pagination.totalItems, so a complete read cannot be shown."
    items = [i for i in items if isinstance(i, dict)]
    if pagination.get("truncated"):
        return None, ("Read stopped at the page limit (" + str(len(items)) + " of " + str(total) + " "
                      + noun + "s); a partial read is not scored.")
    if str(pagination.get("nextCursor") or "").strip() not in ("", "None", "null"):
        return None, ("Only part of the list was read (" + str(len(items)) + " of " + str(total) + " "
                      + noun + "s; more pages remain); a partial read is not scored.")
    if len(items) < total:
        return None, "Read " + str(len(items)) + " of " + str(total) + " " + noun + "s; a partial read is not scored."
    return items, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the pagination block stays visible and a partial read is caught.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def flag_or_none(value):
    """True / False for a SentinelOne boolean (native bool or 'true'/'false'), None when it is not one."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def install_state(agent):
    """True (installed), False (uninstalled or decommissioned) or None (no readable install evidence).
    Only isUninstalled == False, or isActive == True when isUninstalled is absent, shows the agent installed."""
    if coerce_bool(agent.get("isDecommissioned")):
        return False
    uninstalled = flag_or_none(agent.get("isUninstalled"))
    if uninstalled is not None:
        return not uninstalled
    if flag_or_none(agent.get("isActive")) is True:
        return True
    return None


def parse_seen(value):
    """A naive-UTC check-in time, or None when unreadable or more than a day after the read (not evidence)."""
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        when = datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None
    if when > datetime.utcnow() + timedelta(days=1):
        return None
    return when


def fresh_agents(agents):
    """(agents judged, stale count): endpoint rules 2026-09-29, the 15-day window on the newest check-in.

    Same rule as epp/sentinelone/requiredCoveragePercentage.py. An agent whose lastActiveDate is more
    than 15 days before the newest lastActiveDate in the response is stale and left out. When the
    newest check-in is itself more than 15 days old the fleet is dark and every dated agent is stale.
    An agent with no readable lastActiveDate is judged, not dropped.
    """
    seen = [parse_seen(a.get("lastActiveDate")) for a in agents]
    known = [s for s in seen if s is not None]
    if not known:
        return list(agents), 0
    cutoff = max(known) - timedelta(days=ACTIVE_WINDOW_DAYS)
    wall_cutoff = datetime.utcnow() - timedelta(days=ACTIVE_WINDOW_DAYS)
    if max(known) < wall_cutoff:
        cutoff = wall_cutoff
    fresh = []
    stale = 0
    for agent, when in zip(agents, seen):
        if when is not None and when < cutoff:
            stale = stale + 1
        else:
            fresh.append(agent)
    return fresh, stale


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": "SentinelOne", "category": "mdr"},
    )


def transform(input):
    key = "assetInventoryCoveragePercentage"
    meta = {"transformationId": key, "vendor": "SentinelOne", "category": "mdr"}
    validation = extract_validation(input)
    agents, problem = complete_read(raw_body(input), "agent")
    if problem is not None:
        return not_measured(key, problem, validation)
    registered = [a for a in agents if not coerce_bool(a.get("isDecommissioned"))]
    known, stale = fresh_agents(registered)
    if registered and not known:
        return not_measured(key, "All " + str(stale) + " SentinelOne agents last checked in more than "
                            + str(ACTIVE_WINDOW_DAYS) + " days ago; there is nothing to measure.", validation)
    unread = len([a for a in known if install_state(a) is None])
    if known and unread * 2 > len(known):
        return not_measured(key, str(unread) + " of " + str(len(known)) + " SentinelOne agents carry no readable "
                            "isUninstalled flag (or isActive true), so install coverage cannot be shown; "
                            "nothing to measure.", validation)
    installed = [a for a in known if install_state(a)]
    inactive = [a for a in installed if a.get("isActive") is not None and not coerce_bool(a.get("isActive"))]
    summary = {"knownEndpoints": len(known), "installedAgents": len(installed),
               "inactiveInstalledAgents": len(inactive), "staleAgentCount": stale, "unreadAgentCount": unread}
    findings = ["Denominator is the SentinelOne-registered inventory; endpoints never registered with SentinelOne are not visible here."]
    if stale:
        findings.append(str(stale) + " agent(s) last checked in more than " + str(ACTIVE_WINDOW_DAYS)
                        + " days before the newest check-in and are left out of the count (staleAgentCount).")
    if unread:
        findings.append(str(unread) + " agent(s) carry no readable isUninstalled flag (missing or null, and not "
                        "isActive true); they count as not covered (unreadAgentCount).")
    if inactive:
        findings.append(str(len(inactive)) + " installed agent(s) have isActive=false (not online when the check ran); "
                        "they remain installed and are counted as covered.")
    if not known:
        return create_response(
            result={key: 0.0, "knownEndpoints": 0, "installedAgents": 0, "activeAgents": 0, "staleAgentCount": 0},
            validation=validation,
            fail_reasons=["No endpoints are registered with SentinelOne, so no endpoint has an installed agent."],
            recommendations=["Deploy the SentinelOne agent to managed endpoints."],
            input_summary=summary,
            additional_findings=findings,
            metadata=meta,
        )
    pct = round(len(installed) * 100.0 / len(known), 2)
    text = (str(len(installed)) + " of " + str(len(known)) + " known endpoints show the SentinelOne agent installed ("
            + str(pct) + "%).")
    return create_response(
        # activeAgents kept for compatibility; it now carries the installed (covered) count, as in EPP.
        result={key: pct, "knownEndpoints": len(known), "installedAgents": len(installed),
                "activeAgents": len(installed), "staleAgentCount": stale, "unreadAgentCount": unread},
        validation=validation,
        pass_reasons=[text] if len(installed) == len(known) else [],
        fail_reasons=[] if len(installed) == len(known) else [text],
        recommendations=[] if len(installed) == len(known) else
        ["Reinstall the SentinelOne agent on the endpoints where it was uninstalled."],
        input_summary=summary,
        additional_findings=findings,
        metadata=meta,
    )
