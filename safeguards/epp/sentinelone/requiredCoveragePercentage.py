"""Transformation: requiredCoveragePercentage — SentinelOne getAgents
Coverage percentage of endpoints which Endpoint Security is installed.
Uses fully-paginated agent list (follow=true, max_pages=null) so len(items)
equals fleet-wide total.

Coverage counts every enrolled agent that is still installed (not uninstalled
and not decommissioned). It deliberately does NOT gate on isActive: in
SentinelOne isActive reflects only a recent management-console check-in/online
session, so it is false for asleep, offline, or roaming endpoints that remain
fully installed and protected (activeProtection still [edr], mitigationMode
still protect/detect). Gating coverage on isActive understates protection and
produced false "low coverage" failures — e.g. UFT reported 265/919 = 28.84%
while the isEPPConfigured / isEPPEnabled checks found all 919 agents installed
and in an enforcing mitigation mode.
"""

import json
from datetime import datetime, timedelta


def coerce_bool(value):
    """Coerce a SentinelOne boolean-ish field to a real bool.

    The agent payload may carry native booleans or the strings 'true'/'false'
    depending on the collection path; naive truthiness treats the string
    'False' as True, so normalize explicitly.

    NOTE: must not be named with a leading underscore — RestrictedPython (the
    transformation sandbox) rejects all underscore-prefixed identifiers.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() == "true"
    return bool(value)


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
    data, validation = extract_input(input)
    # Read the undrilled response (input.get("data") makes Token-Service pass it whole), so the
    # pagination block is visible and a partial read returns None with a dataCollection error.
    raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
    agents, problem = complete_agent_read(raw)
    if problem is not None:
        return create_response(
            result={"requiredCoveragePercentage": None},
            validation=validation,
            fail_reasons=[problem],
            api_errors=[problem],
            metadata={"transformationId": "requiredCoveragePercentage", "vendor": "SentinelOne", "category": "epp"},
        )
    data, stale_count = fresh_agents(agents)

    # Token-Service preprocessing may unwrap to a bare list of agents (when API
    # response's `data` field is a list) or leave a dict containing `data`.
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    # With follow=true and max_pages=null, the runtime aggregates all pages into data.
    # len(items) is the fleet-wide enrolled count — same scope as our per-agent counts.
    total_enrolled = len(items)

    # An empty judged fleet proves nothing either way: Unevaluated with the reason, never 0%.
    # Either the complete read held no agents, or every agent fell outside the check-in window.
    if total_enrolled == 0:
        reason = (
            f"All {stale_count} SentinelOne agents last checked in more than {ACTIVE_WINDOW_DAYS} days ago; "
            f"there is nothing to measure"
            if stale_count else "No SentinelOne agents were returned; there is nothing to measure"
        )
        return create_response(
            result={
                "requiredCoveragePercentage": None,
                "totalEnrolledAgents": 0,
                "staleAgentCount": stale_count,
            },
            validation=validation,
            api_errors=[reason],
            fail_reasons=[reason],
            recommendations=[
                "Confirm SentinelOne agents are installed and checking in for the configured site or account."
            ],
            input_summary={"totalEnrolledAgents": 0, "staleAgentCount": stale_count},
            metadata={"transformationId": "requiredCoveragePercentage", "vendor": "SentinelOne", "category": "epp"},
        )

    installed_count = 0
    uninstalled_count = 0
    decommissioned_count = 0
    inactive_installed_count = 0

    for agent in items:
        if not isinstance(agent, dict):
            continue
        if coerce_bool(agent.get("isUninstalled")):
            uninstalled_count = uninstalled_count + 1
            continue
        if coerce_bool(agent.get("isDecommissioned")):
            decommissioned_count = decommissioned_count + 1
            continue
        # Enrolled and neither uninstalled nor decommissioned => Endpoint
        # Security IS installed on this endpoint, which is what this metric
        # measures. Do NOT gate on isActive (see module docstring): it only
        # tracks a recent console check-in and flips to false for offline but
        # still-protected endpoints.
        installed_count = installed_count + 1
        is_active = agent.get("isActive")
        if is_active is not None and not coerce_bool(is_active):
            inactive_installed_count = inactive_installed_count + 1

    covered_count = installed_count

    coverage_pct = round((covered_count / total_enrolled) * 100, 2)

    not_covered = total_enrolled - covered_count

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if coverage_pct >= 100.0:
        pass_reasons.append(
            f"All {total_enrolled} enrolled endpoints have the SentinelOne agent installed "
            f"(isUninstalled=false, isDecommissioned=false), yielding 100% Endpoint Security coverage."
        )
    else:
        fail_reasons.append(
            f"{covered_count} of {total_enrolled} enrolled endpoints have the SentinelOne agent "
            f"installed ({coverage_pct}% coverage); {uninstalled_count} are uninstalled and "
            f"{decommissioned_count} are decommissioned, leaving {not_covered} endpoint(s) without "
            f"Endpoint Security installed."
        )
        recommendations.append(
            f"Redeploy the SentinelOne agent to the {not_covered} endpoint(s) that are uninstalled "
            f"or decommissioned to restore full coverage."
        )

    additional_findings = []
    if stale_count > 0:
        additional_findings.append(
            f"{stale_count} agent(s) last checked in more than {ACTIVE_WINDOW_DAYS} days before the newest "
            f"check-in and are left out of the coverage count (staleAgentCount)."
        )
    if uninstalled_count > 0:
        additional_findings.append(
            f"{uninstalled_count} agent(s) have isUninstalled=true and are excluded from the coverage count."
        )
    if decommissioned_count > 0:
        additional_findings.append(
            f"{decommissioned_count} agent(s) have isDecommissioned=true and are excluded from the coverage count."
        )
    if inactive_installed_count > 0:
        additional_findings.append(
            f"{inactive_installed_count} installed agent(s) have isActive=false (no recent console "
            f"check-in). They remain installed and are counted as covered, but are worth reviewing — "
            f"investigate any that have not reported for an extended period as they may be stale records."
        )

    return create_response(
        result={
            "requiredCoveragePercentage": coverage_pct,
            "installedAgents": covered_count,
            # activeAgents retained for backward compatibility; now equals the
            # installed/covered count (no longer gated on isActive).
            "activeAgents": covered_count,
            "inactiveAgents": inactive_installed_count,
            "totalEnrolledAgents": total_enrolled,
            "uninstalledAgents": uninstalled_count,
            "decommissionedAgents": decommissioned_count,
            "staleAgentCount": stale_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "totalEnrolledAgents": total_enrolled,
            "installedAgents": covered_count,
            "activeAgents": covered_count,
            "inactiveAgents": inactive_installed_count,
            "uninstalledAgents": uninstalled_count,
            "decommissionedAgents": decommissioned_count,
            "coveragePercentage": coverage_pct,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
