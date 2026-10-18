"""Transformation: staleAgentOfflineCount - Huntress Managed EDR (MDR), Huntress REST API v1. Not measured (None) on any body that proves nothing."""
import json
from datetime import datetime


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


WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode") or cur.get("status")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error) for the first dict, through any wrapper, that carries key `wanted`."""
    cur = obj
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if wanted in cur:
            return cur, None
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the pagination block stays visible and a partial read is caught.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def parse_time(text):
    """Naive-UTC datetime from an ISO-8601 string, or None."""
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        return datetime.fromisoformat(text[:19])
    except Exception:
        return None


def pct(part, whole):
    return round(100.0 * part / whole, 2) if whole else None


VENDOR = "Huntress"
STALE_DAYS = 15
FUTURE_SLACK_SECONDS = 86400  # a callback time more than a day ahead of now is a fault, not a callback


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )


def complete_list(input, list_key, noun):
    """(items, None) for a complete Huntress list read, else (None, problem).

    Complete means: the `list_key` array beside Huntress's pagination block, no
    next_page_token left, and no Integration-Service `truncated` marker (maxPages hit).
    """
    box, problem = find_key(raw_body(input), list_key)
    if problem is not None:
        return None, "Huntress returned an error instead of a " + noun + " list: " + problem
    if box is None or not isinstance(box.get(list_key), list):
        return None, "No Huntress " + noun + " list in the response; nothing to evaluate."
    pagination = box.get("pagination")
    if not isinstance(pagination, dict):
        return None, "The " + noun + " list carries no pagination block, so a complete read cannot be shown."
    items = [i for i in box[list_key] if isinstance(i, dict)]
    if len(items) != len(box[list_key]):
        return None, "The " + noun + " list holds entries that are not " + noun + " records, so it cannot be scored."
    if pagination.get("truncated"):
        return None, "Read stopped at the page limit (" + str(len(items)) + " " + noun + "s); a partial read is not scored."
    if str(pagination.get("next_page_token") or "").strip() not in ("", "None", "null"):
        return None, "Only part of the " + noun + " list was read (more pages remain); a partial read is not scored."
    return items, None


def now_utc():
    """Evaluation time as a naive UTC datetime (the same clock as evaluatedAt)."""
    return datetime.utcnow()


def usable_callback(agent, now):
    """An agent's last_callback_at as a naive-UTC datetime, or None when it cannot be used.

    A callback time that is more than FUTURE_SLACK_SECONDS ahead of now cannot have happened. It
    is a clock or data fault, so it is not evidence that the agent is alive and is never used.
    A small skew (under a day) is tolerated.
    """
    t = parse_time(agent.get("last_callback_at"))
    if t is None or (t - now).total_seconds() > FUTURE_SLACK_SECONDS:
        return None
    return t


def newest_callback(agents, now=None):
    """The newest usable last_callback_at across every agent in the list, or None."""
    now = now or now_utc()
    times = [usable_callback(a, now) for a in agents]
    times = [t for t in times if t is not None]
    return max(times) if times else None


def agent_windows(agents, now=None):
    """(fresh, stale, undated, future) agents judged against evaluation time, not against each other.

    An agent is fresh when its last_callback_at is within STALE_DAYS of now. Judging against the
    newest callback in the response would always call the newest agent fresh, so a fleet that
    went dark months ago would still read as active. An agent whose last_callback_at is in the
    future is in `future` and is neither fresh nor stale: it can never make the fleet look active.
    """
    now = now or now_utc()
    fresh = []
    stale = []
    undated = []
    future = []
    for a in agents:
        t = usable_callback(a, now)
        if t is not None:
            if (now - t).days <= STALE_DAYS:
                fresh.append(a)
            else:
                stale.append(a)
        elif parse_time(a.get("last_callback_at")) is None:
            undated.append(a)
        else:
            future.append(a)
    return fresh, stale, undated, future


def transform(input):
    key = "staleAgentOfflineCount"
    validation = extract_validation(input)
    agents, problem = complete_list(input, "agents", "agent")
    if problem is not None:
        return not_measured(key, problem, validation)
    if not agents:
        return not_measured(key, "Huntress returned an empty agent list; there is no fleet to count stale agents in.", validation)
    fresh, stale, undated, future = agent_windows(agents)
    # An agent with no usable callback (never called back, or a callback time in the future) is offline.
    count = len(stale) + len(undated) + len(future)
    text = (str(count) + " of " + str(len(agents)) + " Huntress agents have not called back within " + str(STALE_DAYS)
            + " days of the evaluation time (" + str(len(undated)) + " never called back, " + str(len(future))
            + " with a callback time in the future, ignored).")
    return create_response(
        result={key: count, "totalAgents": len(agents), "activeAgents": len(fresh)},
        validation=validation,
        pass_reasons=[text] if count == 0 else [],
        fail_reasons=[text] if count else [],
        recommendations=["Investigate or uninstall agents that have stopped checking in."] if count else [],
        input_summary={"totalAgents": len(agents), "staleOrNeverSeen": count},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )
