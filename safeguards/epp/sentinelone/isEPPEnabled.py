
import json
from datetime import datetime, timedelta


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
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



def find_agent_list(obj):
    """(agents, pagination, error) from the getEndpoints response, whatever wrapper Token-Service hands over."""
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


def complete_agent_read(raw):
    """(agents, None) for a complete GET /agents read, else (None, problem).

    Complete means: an agent list with SentinelOne's pagination block, a numeric totalItems, no
    nextCursor left (every page read), no IS `truncated` marker (maxPages stopped the pager), and
    at least totalItems agents. Anything else is a partial or unreadable read and is not scored.
    """
    agents, pagination, error = find_agent_list(raw)
    if error is not None:
        return None, "SentinelOne returned an error instead of an agent list: " + error
    if agents is None:
        return None, "No SentinelOne agent list in the response; nothing to evaluate."
    if pagination is None:
        return None, "The agent list carries no pagination block, so a complete read cannot be shown."
    total = pagination.get("totalItems")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return None, "pagination.totalItems is missing, so a complete read cannot be shown."
    agents = [a for a in agents if isinstance(a, dict)]
    if pagination.get("truncated"):
        return None, ("Read stopped at the page limit (" + str(len(agents)) + " of " + str(total)
                      + " agents); a partial read is not scored.")
    if str(pagination.get("nextCursor") or "").strip() not in ("", "None", "null"):
        return None, ("Only the first page was read (" + str(len(agents)) + " of " + str(total)
                      + " agents; more pages remain); a partial read is not scored.")
    if len(agents) < total:
        return None, "Read " + str(len(agents)) + " of " + str(total) + " agents; a partial read is not scored."
    return agents, None

ACTIVE_WINDOW_DAYS = 15


def parse_seen(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def fresh_agents(agents):
    """(agents judged, stale count): endpoint rules 2026-09-29, the 15-day window on the newest check-in.

    An agent whose lastActiveDate is more than 15 days before the newest lastActiveDate in the response is
    stale: left out of the judgement and reported as staleAgentCount. When the newest check-in is itself
    more than 15 days old the fleet is dark and every dated agent is stale. An agent with no readable
    lastActiveDate is judged, not dropped.
    """
    agents = [a for a in agents if isinstance(a, dict)]
    seen = [parse_seen(a.get("lastActiveDate")) for a in agents]
    known = [s for s in seen if s is not None]
    if not known:
        return agents, 0
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


def transform(input):
    """isEPPEnabled (SentinelOne, GET /web/api/v2.1/agents).

    An agent has endpoint protection ENABLED when its mitigationMode is "protect" or "detect"
    (the engine is running; "none" disables it) AND it reports a non-empty activeProtection list.
    True only when at least one agent is returned and every returned agent is enabled; the
    percentage is emitted as eppEnabledPercentage. Enrolment alone (the old totalItems > 0 rule)
    is not evidence: an agent with mitigationMode "none" is enrolled and unprotected.
    An error body, an unreadable or partial agent list and an empty judged fleet (no agents, or
    all outside the check-in window) are Unevaluated (None) with the reason, never False.
    """
    data, validation = extract_input(input)
    # Read the undrilled response (input.get("data") makes Token-Service pass it whole), so the
    # pagination block is visible and a partial read returns None with a dataCollection error.
    raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
    agents, problem = complete_agent_read(raw)
    if problem is not None:
        return create_response(
            result={"isEPPEnabled": None},
            validation=validation,
            fail_reasons=[problem],
            api_errors=[problem],
            metadata={"transformationId": "isEPPEnabled", "vendor": "SentinelOne", "category": "epp"},
        )
    data, stale_count = fresh_agents(agents)
    if isinstance(data, dict) and (data.get("errors") or data.get("error")):
        reason = "SentinelOne returned an error instead of an agent list"
        return create_response(
            result={"isEPPEnabled": False, "eppEnabledPercentage": 0, "totalAgents": 0, "enabledAgents": 0},
            validation=validation, api_errors=[reason], fail_reasons=[reason],
            metadata={"transformationId": "isEPPEnabled", "vendor": "SentinelOne", "category": "epp"},
        )
    total_items = 0
    if isinstance(data, list):
        agents = data
    elif isinstance(data, dict):
        agents = data.get("data")
        pagination = data.get("pagination") if isinstance(data.get("pagination"), dict) else {}
        total_items = pagination.get("totalItems") or 0
    else:
        agents = None
    if not isinstance(agents, list):
        agents = []
    agents = [a for a in agents if isinstance(a, dict)]
    sampled = len(agents)
    total_items = int(total_items) if total_items else sampled

    # An empty judged fleet proves nothing either way: Unevaluated with the reason, never a False.
    # Either the complete read held no agents, or every agent fell outside the check-in window.
    if sampled == 0:
        reason = (
            "All " + str(stale_count) + " SentinelOne agents last checked in more than "
            + str(ACTIVE_WINDOW_DAYS) + " days ago; there is nothing to measure"
            if stale_count else "No SentinelOne agents were returned; there is nothing to measure"
        )
        return create_response(
            result={"isEPPEnabled": None, "totalAgents": total_items, "sampledAgents": 0, "staleAgentCount": stale_count},
            validation=validation,
            api_errors=[reason],
            fail_reasons=[reason],
            recommendations=["Confirm SentinelOne agents are installed and checking in for the configured site or account"],
            input_summary={"totalAgents": total_items, "sampledAgents": 0, "staleAgentCount": stale_count},
            metadata={"transformationId": "isEPPEnabled", "vendor": "SentinelOne", "category": "epp"},
        )

    enabled = 0
    disabled_names = []
    for agent in agents:
        mode = str(agent.get("mitigationMode") or "").lower()
        active = agent.get("activeProtection")
        has_protection = isinstance(active, list) and len(active) > 0
        if mode in ("protect", "detect") and has_protection:
            enabled = enabled + 1
        else:
            disabled_names.append(str(agent.get("computerName") or agent.get("uuid") or "unknown"))

    pct = (enabled * 100) // sampled if sampled else 0
    is_enabled = sampled > 0 and enabled == sampled
    summary = (
        str(enabled) + " of " + str(sampled) + " returned agents (" + str(pct) + "%) run protection "
        "(mitigationMode protect or detect, activeProtection reported)"
    )
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    findings = []
    if is_enabled:
        pass_reasons.append(summary)
    else:
        fail_reasons.append(summary)
        findings.append("Agents without protection: " + ", ".join(disabled_names[:5]) + ("..." if len(disabled_names) > 5 else ""))
        recommendations.append("Set mitigationMode to protect (or detect) in the agent policy for every agent")
    if stale_count:
        findings.append(str(stale_count) + " agent(s) last checked in more than " + str(ACTIVE_WINDOW_DAYS)
                        + " days before the newest check-in and are not judged (staleAgentCount)")
    if total_items > sampled:
        findings.append("Judged on the " + str(sampled) + " agents returned of " + str(total_items) + " enrolled")
    return create_response(
        result={
            "isEPPEnabled": is_enabled,
            "eppEnabledPercentage": pct,
            "totalAgents": total_items,
            "sampledAgents": sampled,
            "staleAgentCount": stale_count,
            "enabledAgents": enabled,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=findings,
        input_summary={"totalAgents": total_items, "sampledAgents": sampled, "enabledAgents": enabled},
        metadata={"transformationId": "isEPPEnabled", "vendor": "SentinelOne", "category": "epp"},
    )
