"""
Transformation: requiredConfigurationPercentage
Vendor: SentinelOne
Category: epp
Method: getEndpoints

Percentage of enrolled agents that have EPP properly configured. An agent is
considered "configured" when ALL of the following hold:
  - mitigationMode is 'protect' or 'detect' (not 'none')
  - activeProtection contains at least one entry (e.g. 'edr')
  - isUpToDate is True

Denominator is len(items) — Token-Service preprocessing strips pagination, so
len(items) is the agents-this-page count for the configured site (after the
siteIds filter on /agents).
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
            result={"requiredConfigurationPercentage": None},
            validation=validation,
            fail_reasons=[problem],
            api_errors=[problem],
            metadata={"transformationId": "requiredConfigurationPercentage", "vendor": "SentinelOne", "category": "epp"},
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

    total_enrolled = len(items)

    # An empty fleet proves nothing either way: Unevaluated with the reason, never 0%.
    if total_enrolled == 0:
        reason = "No SentinelOne agents were returned; there is nothing to measure"
        return create_response(
            result={
                "requiredConfigurationPercentage": None,
                "configuredAgents": 0,
                "totalEnrolledAgents": 0,
            },
            validation=validation,
            api_errors=[reason],
            fail_reasons=[reason],
            recommendations=["Confirm SentinelOne agents are installed and checking in for the configured site or account."],
            input_summary={"totalEnrolledAgents": 0, "configuredAgents": 0},
            metadata={
                "transformationId": "requiredConfigurationPercentage",
                "vendor": "SentinelOne",
                "category": "epp",
            },
        )

    configured = 0
    not_configured_reasons = {"badMitigation": 0, "noActiveProtection": 0, "outOfDate": 0}
    examples = {"badMitigation": [], "noActiveProtection": [], "outOfDate": []}

    for agent in items:
        if not isinstance(agent, dict):
            continue
        name = agent.get("computerName") or agent.get("uuid") or "unknown"
        mitigation = agent.get("mitigationMode") or ""
        active_protection = agent.get("activeProtection") or []
        if not isinstance(active_protection, list):
            active_protection = []
        is_up_to_date = bool(agent.get("isUpToDate"))

        is_mitigation_ok = mitigation in ("protect", "detect")
        has_protection = len(active_protection) > 0

        if is_mitigation_ok and has_protection and is_up_to_date:
            configured = configured + 1
            continue

        if not is_mitigation_ok:
            not_configured_reasons["badMitigation"] = not_configured_reasons["badMitigation"] + 1
            if len(examples["badMitigation"]) < 3:
                examples["badMitigation"].append(name)
        if not has_protection:
            not_configured_reasons["noActiveProtection"] = not_configured_reasons["noActiveProtection"] + 1
            if len(examples["noActiveProtection"]) < 3:
                examples["noActiveProtection"].append(name)
        if not is_up_to_date:
            not_configured_reasons["outOfDate"] = not_configured_reasons["outOfDate"] + 1
            if len(examples["outOfDate"]) < 3:
                examples["outOfDate"].append(name)

    pct = round((configured / total_enrolled) * 100, 2)
    not_configured = total_enrolled - configured

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    if pct >= 100.0:
        pass_reasons.append(
            f"All {total_enrolled} enrolled agents are properly configured "
            f"(mitigationMode in protect/detect, activeProtection populated, isUpToDate=True)."
        )
    else:
        fail_reasons.append(
            f"{configured} of {total_enrolled} enrolled agents are properly configured "
            f"({pct}%). {not_configured} agents are missing one or more required settings."
        )
        if not_configured_reasons["badMitigation"] > 0:
            additional_findings.append(
                f"{not_configured_reasons['badMitigation']} agents have mitigationMode "
                f"not in protect/detect (e.g. {', '.join(examples['badMitigation'])})."
            )
        if not_configured_reasons["noActiveProtection"] > 0:
            additional_findings.append(
                f"{not_configured_reasons['noActiveProtection']} agents have empty activeProtection "
                f"(e.g. {', '.join(examples['noActiveProtection'])})."
            )
        if not_configured_reasons["outOfDate"] > 0:
            additional_findings.append(
                f"{not_configured_reasons['outOfDate']} agents are not up-to-date "
                f"(e.g. {', '.join(examples['outOfDate'])})."
            )
        recommendations.append(
            "Review agent policies in the SentinelOne console: ensure mitigationMode is set to "
            "'protect' or 'detect', EDR/activeProtection modules are enabled, and agents are running "
            "the latest version."
        )

    return create_response(
        result={
            "requiredConfigurationPercentage": pct,
            "configuredAgents": configured,
            "totalEnrolledAgents": total_enrolled,
            "agentsBadMitigation": not_configured_reasons["badMitigation"],
            "agentsNoActiveProtection": not_configured_reasons["noActiveProtection"],
            "agentsOutOfDate": not_configured_reasons["outOfDate"],
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        additional_findings=additional_findings,
        input_summary={
            "totalEnrolledAgents": total_enrolled,
            "configuredAgents": configured,
            "configurationPercentage": pct,
        },
        metadata={
            "transformationId": "requiredConfigurationPercentage",
            "vendor": "SentinelOne",
            "category": "epp",
        },
    )
