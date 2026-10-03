"""Transformation: isMDRLoggingEnabled (Rapid7 MDR / InsightIDR, method getHealthMetrics).

True when at least one InsightIDR event source is RUNNING and reported (last_active) in the
last 24 hours, read from the health-metrics API. False on a complete read with no running,
recently active event source.

Fail closed: returns isMDRLoggingEnabled=None (never True) when the body is not a readable InsightIDR
response, carries a vendor error, or does not hold enough evidence to decide.
"""
import json
from datetime import datetime, timedelta

KEY = "isMDRLoggingEnabled"


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        value = json.loads(value) if value.strip() else None
    return value


def unwrap(value):
    for depth in range(6):
        if isinstance(value, dict) and "validation" in value and isinstance(value.get("data"), dict):
            value = value["data"]
            continue
        if not isinstance(value, dict) or "data" in value:
            break
        moved = False
        for w in ["apiResponse", "_response_data", "response", "result", "Output", "api_response"]:
            inner = value.get(w)
            if isinstance(inner, (str, bytes)):
                try:
                    inner = parse(inner)
                except Exception:
                    inner = None
            if isinstance(inner, dict):
                value = inner
                moved = True
                break
        if not moved:
            break
    return value


def respond(value, pass_reasons=None, fail_reasons=None, summary=None, problem=None):
    result = {KEY: value}
    for k in (summary or {}):
        result[k] = summary[k]
    errors = [problem] if problem else []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if problem else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": (fail_reasons or []) + errors,
                "recommendations": [],
                "additionalFindings": [],
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "2.0",
                "transformationId": KEY,
                "vendor": "Rapid7 MDR",
                "category": "mdr",
            },
        },
    }


def envelope(input):
    """The raw response body. Reading input.get("data") here opts this file into Token-Service's enriched
    input contract ({"data": <raw envelope>, "validation": ...}); without it the executor drills into the
    vendor's own "data" list and the paging metadata (total_data) is lost."""
    if isinstance(input, dict) and "validation" in input and "data" in input:
        return unwrap(parse(input.get("data")))
    return unwrap(parse(input))


def unevaluated(problem):
    return respond(None, problem=problem)


def vendor_error(data):
    for k in ("error", "errors", "message", "status_code", "statusCode"):
        if k in data and data.get(k) not in (None, "", [], {}):
            return True
    return False


def to_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def parse_time(value):
    if not isinstance(value, str) or len(value) < 19:
        return None
    # No strptime: the Token-Service sandbox does not allow it. ISO 8601 "2026-10-01T02:13:08.813Z" (UTC).
    if value[4] != "-" or value[7] != "-" or value[10] not in ("T", " ") or value[13] != ":" or value[16] != ":":
        return None
    try:
        return datetime(int(value[0:4]), int(value[5:7]), int(value[8:10]), int(value[11:13]), int(value[14:16]), int(value[17:19]))
    except Exception:
        return None


def read_health(input):
    """(items, complete, problem) from a merged /idr/v1/health-metrics read."""
    data = envelope(input)
    if not isinstance(data, dict) or not isinstance(data.get("data"), list) or not isinstance(data.get("metadata"), dict):
        return None, False, "Not an InsightIDR /idr/v1/health-metrics body (data list + metadata); nothing to evaluate."
    if vendor_error(data):
        return None, False, "InsightIDR returned an error body; nothing to evaluate."
    items = [i for i in data["data"] if isinstance(i, dict) and isinstance(i.get("rrn"), str)]
    total = to_int(data["metadata"].get("total_data"))
    if total is None:
        return None, False, "metadata.total_data is missing, so a complete read cannot be shown."
    if len(items) == 0:
        return None, False, "InsightIDR returned no health-metric resources; nothing to evaluate."
    return items, len(items) >= total, None

WINDOW_HOURS = 24


def transform(input):
    try:
        items, complete, problem = read_health(input)
        if problem:
            return unevaluated(problem)
        cutoff = datetime.utcnow() - timedelta(hours=WINDOW_HOURS)
        sources = [i for i in items if ":eventsource:" in i["rrn"]]
        running = [i for i in sources if str(i.get("state") or "").upper() == "RUNNING"]
        recent = []
        unparsed = 0
        for i in running:
            t = parse_time(i.get("last_active"))
            if t is None:
                unparsed = unparsed + 1
            elif t >= cutoff:
                recent.append(i)
        summary = {"eventSources": len(sources), "runningEventSources": len(running),
                   "runningActiveLast24h": len(recent), "completeRead": complete}
        if recent:
            return respond(True, pass_reasons=[str(len(recent)) + " of " + str(len(sources)) +
                           " InsightIDR event sources are RUNNING and reported in the last 24 hours."], summary=summary)
        if unparsed:
            return unevaluated(str(unparsed) + " running event sources have no readable last_active time, so their activity is unknown.")
        if not complete:
            return unevaluated("Read only part of the health metrics and found no recently active event source; a partial read cannot show logging is off.")
        if not sources:
            return respond(False, fail_reasons=["InsightIDR health metrics list no event sources: no logs are being collected."], summary=summary)
        return respond(False, fail_reasons=["None of " + str(len(sources)) +
                       " InsightIDR event sources is RUNNING with activity in the last 24 hours."], summary=summary)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e))
