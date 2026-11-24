"""Transformation: offlineSensorCount - Kaseya Datto EDR (Endpoint Security), method getAgents.

Count of installed agents inside the WINDOW_DAYS-day window that Datto EDR reports as not active
(the vendor's own online/heartbeat flag). Agents outside the window are reported as
staleSensorCount, not here. The window is measured from the newest heartbeat in the response,
not the wall clock (same rule as SentinelOne). None when the agent list is missing, an error,
possibly truncated, or holds no installed agent.
"""
import json
from datetime import datetime

WINDOW_DAYS = 15
# getAgents asks for filter={"limit":1000}; a response that fills the limit may be cut short.
READ_LIMIT = 1000


def coerce_bool(value):
    """Real bool from a Datto EDR boolean-ish field (native bool or 'true'/'false')."""
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
    """(agents, error) from a Datto EDR /api/Agents response, whatever wrapper Token-Service hands over."""
    cur = obj
    for depth in range(6):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if isinstance(cur, list):
            return cur, None
        if not isinstance(cur, dict):
            return None, None
        if cur.get("error") or cur.get("errors"):
            detail = cur.get("error") or cur.get("errors")
            if isinstance(detail, dict):
                detail = detail.get("message") or detail
            return None, json.dumps(detail)[:300]
        nxt = None
        for key in ["data", "result", "response", "apiResponse", "api_response", "Output", "items"]:
            if isinstance(cur.get(key), (dict, list, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def complete_read(input):
    """(agents, None) for a complete agent list, else (None, problem)."""
    raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
    agents, error = find_list(raw)
    if error is not None:
        return None, "Datto EDR returned an error instead of an agent list: " + error
    if agents is None:
        return None, "No Datto EDR agent list in the response; nothing to evaluate."
    if len(agents) >= READ_LIMIT:
        return None, ("The agent list filled the " + str(READ_LIMIT) + "-agent read limit, so it may be cut short;"
                      " a partial read is not scored.")
    return [a for a in agents if isinstance(a, dict)], None


def installed_agents(agents):
    """Agents still installed: type installed (or absent) and not marked for uninstall."""
    out = []
    for agent in agents:
        kind = str(agent.get("type") or "installed").strip().lower()
        if kind != "installed" or coerce_bool(agent.get("markedForUninstall")):
            continue
        out.append(agent)
    return out


def heartbeat(agent):
    """Naive-UTC datetime from the agent heartbeat, or None when absent or unparseable."""
    text = agent.get("heartbeat")
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        return datetime.fromisoformat(text[:19])
    except Exception:
        return None


def split_window(installed):
    """(judged, stale, newest): judged agents sent a heartbeat within WINDOW_DAYS of the newest one."""
    seen = [(a, heartbeat(a)) for a in installed]
    dates = [d for a, d in seen if d is not None]
    if not dates:
        return [], [a for a, d in seen], None
    newest = max(dates)
    judged = []
    stale = []
    for a, d in seen:
        if d is not None and (newest - d).days <= WINDOW_DAYS:
            judged.append(a)
        else:
            stale.append(a)
    return judged, stale, newest


def name_of(agent):
    return str(agent.get("hostname") or agent.get("name") or agent.get("id") or "unknown")


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": "Kaseya Datto EDR", "category": "epp"},
    )


def transform(input):
    key = "offlineSensorCount"
    validation = extract_validation(input)
    agents, problem = complete_read(input)
    if problem is not None:
        return not_measured(key, problem, validation)
    installed = installed_agents(agents)
    if not installed:
        return not_measured(key, "No installed Datto EDR agents in the response; there is no device to judge.", validation)
    judged, stale, newest = split_window(installed)
    if not judged:
        return not_measured(key, "All " + str(len(installed)) + " installed agents are outside the " + str(WINDOW_DAYS)
                            + "-day window (staleSensorCount); none is left to judge.", validation)
    offline = [a for a in judged if not coerce_bool(a.get("active"))]
    count = len(offline)
    text = (str(count) + " offline of " + str(len(judged)) + " agents that checked in within " + str(WINDOW_DAYS)
            + " days of the newest heartbeat (" + str(len(stale)) + " stale agents not judged).")
    findings = []
    if offline:
        findings.append("Offline: " + ", ".join(name_of(a) for a in offline[:10]) + ("" if count <= 10 else ", ..."))
    return create_response(
        result={key: count, "judgedAgents": len(judged), "installedAgents": len(installed),
                "staleSensorCount": len(stale), "windowDays": WINDOW_DAYS,
                "newestCheckIn": newest.isoformat() if newest is not None else None},
        validation=validation,
        pass_reasons=[text] if count == 0 else [],
        fail_reasons=[text] if count else [],
        recommendations=["Bring offline endpoints back online or check why the agent is not reporting."] if count else [],
        additional_findings=findings,
        input_summary={"installedAgents": len(installed), "judgedAgents": len(judged), "offline": count},
        metadata={"transformationId": key, "vendor": "Kaseya Datto EDR", "category": "epp"},
    )
