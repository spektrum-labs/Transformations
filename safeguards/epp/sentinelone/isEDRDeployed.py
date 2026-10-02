"""Transformation: isEDRDeployed (SentinelOne, GET /web/api/v2.1/agents, method getEndpoints).

Source field: each agent's activeProtection list. "edr" in it means the agent is running SentinelOne's EDR
(Deep Visibility / Storyline) protection; isEPPLoggingEnabled reads the same field for EDR telemetry.

True when at least one installed agent (not uninstalled, not decommissioned) inside the 15-day check-in window
reports "edr" in activeProtection -- "the EDR sensor is deployed", the CrowdStrike Falcon isEDRDeployed
convention. Breadth is requiredCoveragePercentage. edrDeployedPercentage (whole number, of the judged agents)
is emitted as evidence. False on a complete read where no judged agent reports "edr".

Not evaluated (isEDRDeployed None, dataCollection "error"): a partial or unreadable agent read (no pagination
block, non-numeric totalItems, a nextCursor left, an IS truncated marker, fewer agents than totalItems), an
error body, an empty fleet, or no agent inside the check-in window.
"""
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


KEY = "isEDRDeployed"
META = {"transformationId": "isEDRDeployed", "vendor": "SentinelOne", "category": "epp"}


def flag(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def transform(input):
    data, validation = extract_input(input)
    raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
    agents, problem = complete_agent_read(raw)
    if problem is None and not agents:
        problem = "SentinelOne returned no agents; an empty fleet proves nothing about EDR deployment."
    if problem is not None:
        return create_response(result={KEY: None}, validation=validation, fail_reasons=[problem],
                               api_errors=[problem], metadata=META)
    judged, stale_count = fresh_agents(agents)
    installed = [a for a in judged if not flag(a.get("isUninstalled")) and not flag(a.get("isDecommissioned"))]
    if not installed:
        problem = ("No installed SentinelOne agent checked in within " + str(ACTIVE_WINDOW_DAYS)
                   + " days of the newest check-in; EDR deployment cannot be judged.")
        return create_response(result={KEY: None, "staleAgentCount": stale_count}, validation=validation,
                               fail_reasons=[problem], api_errors=[problem], metadata=META)
    with_edr = []
    without = []
    for a in installed:
        active = a.get("activeProtection")
        modules = [str(m).strip().lower() for m in active] if isinstance(active, list) else []
        if "edr" in modules:
            with_edr.append(a)
        else:
            without.append(str(a.get("computerName") or a.get("uuid") or "unknown"))
    pct = (len(with_edr) * 100) // len(installed)
    deployed = len(with_edr) > 0
    summary = (str(len(with_edr)) + " of " + str(len(installed)) + " installed agents (" + str(pct)
               + "%) report edr in activeProtection")
    findings = []
    if without:
        findings.append("Agents without edr: " + ", ".join(without[:5]) + ("..." if len(without) > 5 else ""))
    if stale_count:
        findings.append(str(stale_count) + " agent(s) last checked in more than " + str(ACTIVE_WINDOW_DAYS)
                        + " days before the newest check-in and are not judged (staleAgentCount)")
    return create_response(
        result={KEY: deployed, "edrDeployedPercentage": pct, "edrAgents": len(with_edr),
                "judgedAgents": len(installed), "staleAgentCount": stale_count, "totalAgents": len(agents)},
        validation=validation,
        pass_reasons=[summary] if deployed else [],
        fail_reasons=[] if deployed else [summary + "; no agent runs SentinelOne EDR"],
        recommendations=[] if deployed else ["Enable EDR (Deep Visibility) in the SentinelOne policy and licence the agents for it"],
        additional_findings=findings,
        input_summary={"totalAgents": len(agents), "judgedAgents": len(installed), "edrAgents": len(with_edr)},
        metadata=META,
    )
