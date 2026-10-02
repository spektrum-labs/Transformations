"""
Transformation: isEPPEnabledForCriticalSystems
Vendor: SentinelOne
Category: epp
Method: getEndpoints

Confirms EPP coverage on systems classified as "critical." SentinelOne does not
have a built-in "critical" tag, so we proxy critical-system identity by
machineType=='server'. (Customers that classify critical systems differently —
via groupName or tags — should refine this transformation.)

Pass logic:
  - If servers are present in the fleet, ALL servers must have active EPP
    (mitigationMode in protect/detect AND activeProtection populated).
  - If no servers are present in the fleet, pass with an additional finding
    noting that no critical systems were identified — endpoint coverage is
    evaluated separately by isEPPEnabled / isEPPDeployed.
"""
import json
from datetime import datetime, timezone


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
        "evaluatedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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


def is_critical(agent):
    """Heuristic for 'critical system' — currently machineType == 'server'."""
    machine_type = (agent.get("machineType") or "").lower() if isinstance(agent.get("machineType"), str) else ""
    return machine_type == "server"


def is_protected(agent):
    """An agent is considered EPP-protected when mitigation is active and protection modules are reporting."""
    mitigation = agent.get("mitigationMode") or ""
    active_protection = agent.get("activeProtection") or []
    if not isinstance(active_protection, list):
        active_protection = []
    return mitigation in ("protect", "detect") and len(active_protection) > 0



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

def transform(input):
    data, validation = extract_input(input)
    # Read the undrilled response (input.get("data") makes Token-Service pass it whole), so the
    # pagination block is visible and a partial read returns None with a dataCollection error.
    raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
    agents, problem = complete_agent_read(raw)
    if problem is not None:
        return create_response(
            result={"isEPPEnabledForCriticalSystems": None},
            validation=validation,
            fail_reasons=[problem],
            api_errors=[problem],
            metadata={"transformationId": "isEPPEnabledForCriticalSystems", "vendor": "SentinelOne", "category": "epp"},
        )
    data = agents

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    total = len(items)
    critical_systems = [a for a in items if isinstance(a, dict) and is_critical(a)]
    critical_count = len(critical_systems)
    unprotected_critical = [a for a in critical_systems if not is_protected(a)]
    unprotected_names = [
        a.get("computerName") or a.get("uuid") or "unknown" for a in unprotected_critical[:5]
    ]

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    # An empty fleet proves nothing either way: Unevaluated with the reason, never a False.
    if total == 0:
        reason = "No SentinelOne agents were returned; there is nothing to measure"
        return create_response(
            result={
                "isEPPEnabledForCriticalSystems": None,
                "criticalSystemsTotal": 0,
                "criticalSystemsProtected": 0,
                "criticalSystemsUnprotected": 0,
                "fleetTotal": 0,
            },
            validation=validation,
            api_errors=[reason],
            fail_reasons=[reason],
            recommendations=["Confirm SentinelOne agents are installed and checking in for the configured site or account."],
            input_summary={"fleetTotal": 0, "criticalSystemsTotal": 0},
            metadata={
                "transformationId": "isEPPEnabledForCriticalSystems",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    if critical_count == 0:
        # No servers in the fleet; pass with a finding so reviewers understand the scope.
        additional_findings.append(
            f"No critical systems (machineType='server') were identified in the fleet of "
            f"{total} agents. Either no servers are managed by SentinelOne, or critical "
            f"classification needs a different heuristic (e.g. tag or groupName)."
        )
        pass_reasons.append(
            "No critical systems identified — vacuously passes. EPP coverage on endpoints "
            "is evaluated separately by isEPPEnabled / isEPPDeployed."
        )
        is_pass = True
    elif len(unprotected_critical) == 0:
        is_pass = True
        pass_reasons.append(
            f"All {critical_count} critical system(s) (machineType='server') have EPP "
            f"actively protecting them (mitigationMode in protect/detect, activeProtection populated)."
        )
    else:
        is_pass = False
        fail_reasons.append(
            f"{len(unprotected_critical)} of {critical_count} critical systems are not "
            f"protected by EPP (e.g. {', '.join(unprotected_names)})."
        )
        recommendations.append(
            "Verify EPP policy on identified servers. Set mitigationMode to 'protect' or 'detect' "
            "and ensure activeProtection modules (edr, etc.) are enabled in the agent policy."
        )

    return create_response(
        result={
            "isEPPEnabledForCriticalSystems": is_pass,
            "criticalSystemsTotal": critical_count,
            "criticalSystemsProtected": critical_count - len(unprotected_critical),
            "criticalSystemsUnprotected": len(unprotected_critical),
            "fleetTotal": total,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "fleetTotal": total,
            "criticalSystemsTotal": critical_count,
            "criticalSystemsProtected": critical_count - len(unprotected_critical),
            "criticalSystemsUnprotected": len(unprotected_critical),
        },
        metadata={
            "transformationId": "isEPPEnabledForCriticalSystems",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
