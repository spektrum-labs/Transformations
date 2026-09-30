"""Transformation: agentUpToDatePercentage - SentinelOne Vigilance MDR, method getAgents.

Percentage of installed agents (not uninstalled, not decommissioned) reporting isUpToDate=true.
None when the agent list is missing, an error, or partial, or when no installed agent carries an
isUpToDate field at all.
"""
import json
from datetime import datetime


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


def installed_agents(agents):
    """Agents still installed: not uninstalled and not decommissioned."""
    out = []
    for agent in agents:
        if coerce_bool(agent.get("isUninstalled")) or coerce_bool(agent.get("isDecommissioned")):
            continue
        out.append(agent)
    return out


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": "SentinelOne", "category": "mdr"},
    )


def transform(input):
    key = "agentUpToDatePercentage"
    validation = extract_validation(input)
    agents, problem = complete_read(raw_body(input), "agent")
    if problem is not None:
        return not_measured(key, problem, validation)
    installed = installed_agents(agents)
    if not installed:
        return create_response(
            result={key: 0.0, "installedAgents": 0, "upToDateAgents": 0},
            validation=validation,
            fail_reasons=["The SentinelOne tenant has no installed agents, so none is up to date."],
            input_summary={"installedAgents": 0},
            metadata={"transformationId": key, "vendor": "SentinelOne", "category": "mdr"},
        )
    reported = [a for a in installed if "isUpToDate" in a]
    if not reported:
        return not_measured(key, "No installed agent carries an isUpToDate field; agent version currency cannot be judged.", validation)
    current = [a for a in reported if coerce_bool(a.get("isUpToDate"))]
    pct = round(len(current) * 100.0 / len(installed), 2)
    text = str(len(current)) + " of " + str(len(installed)) + " installed agents report isUpToDate=true (" + str(pct) + "%)."
    findings = []
    if len(reported) < len(installed):
        findings.append(str(len(installed) - len(reported)) + " installed agent(s) carry no isUpToDate field and count as not up to date.")
    return create_response(
        result={key: pct, "installedAgents": len(installed), "upToDateAgents": len(current)},
        validation=validation,
        pass_reasons=[text] if len(current) == len(installed) else [],
        fail_reasons=[] if len(current) == len(installed) else [text],
        input_summary={"installedAgents": len(installed), "upToDateAgents": len(current)},
        additional_findings=findings,
        metadata={"transformationId": key, "vendor": "SentinelOne", "category": "mdr"},
    )
