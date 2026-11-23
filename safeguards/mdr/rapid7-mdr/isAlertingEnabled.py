"""Transformation: isAlertingEnabled (Rapid7 MDR / InsightIDR, method listInvestigations).

Same evidence and rule as isAlertingConfigured.py (the NIST CSF key): alerting is on when InsightIDR detection
alerts are opening investigations. Separate file because the criteria key is part of the output contract.

True when InsightIDR detection alerts opened at least one investigation (source == "ALERT")
in the last 90 days. False only on a complete read where investigations exist but none was
alert-sourced in that window.

Fail closed: returns isAlertingEnabled=None (never True) when the body is not a readable InsightIDR
response, carries a vendor error, or does not hold enough evidence to decide.
"""
import json
from datetime import datetime, timedelta

KEY = "isAlertingEnabled"


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


def read_investigations(input):
    """(investigations, complete, problem) from a merged /idr/v2/investigations read."""
    data = envelope(input)
    if not isinstance(data, dict) or not isinstance(data.get("data"), list) or not isinstance(data.get("metadata"), dict):
        return None, False, "Not an InsightIDR /idr/v2/investigations body (data list + metadata); nothing to evaluate."
    if vendor_error(data):
        return None, False, "InsightIDR returned an error body; nothing to evaluate."
    items = [i for i in data["data"] if isinstance(i, dict)]
    # Only investigation records are evidence. A health-metrics or other InsightIDR list has the same envelope,
    # and counting its rows as "investigations, none alert-sourced" would answer False from the wrong body.
    for i in items:
        if not str(i.get("rrn") or "").startswith("rrn:investigation:") or "source" not in i:
            return None, False, "The list holds records that are not InsightIDR investigations; nothing to evaluate."
    total = to_int(data["metadata"].get("total_data"))
    if total is None:
        return None, False, "metadata.total_data is missing, so a complete read cannot be shown."
    if len(items) == 0:
        return None, False, "InsightIDR returned no investigations; zero investigations proves nothing either way."
    return items, len(items) >= total, None

WINDOW_DAYS = 90


def transform(input):
    try:
        items, complete, problem = read_investigations(input)
        if problem:
            return unevaluated(problem)
        cutoff = datetime.utcnow() - timedelta(days=WINDOW_DAYS)
        alert_sourced = [i for i in items if str(i.get("source") or "").upper() == "ALERT"]
        recent = []
        unparsed = 0
        for i in alert_sourced:
            t = parse_time(i.get("created_time"))
            if t is None:
                unparsed = unparsed + 1
            elif t >= cutoff:
                recent.append(i)
        summary = {"investigationsRead": len(items), "alertSourcedInvestigations": len(alert_sourced),
                   "alertSourcedLast90Days": len(recent), "completeRead": complete}
        if recent:
            newest = max([str(i.get("created_time") or "") for i in recent])
            return respond(True, pass_reasons=[str(len(recent)) + " investigations were opened by InsightIDR detection alerts in the last " +
                           str(WINDOW_DAYS) + " days (newest " + newest + ")."], summary=summary)
        if unparsed:
            return unevaluated(str(unparsed) + " alert-sourced investigations have no readable created_time, so their age is unknown.")
        if not complete:
            return unevaluated("Read only part of the investigations and none was alert-sourced in the window; a partial read cannot show alerting is off.")
        return respond(False, fail_reasons=["None of " + str(len(items)) + " InsightIDR investigations was opened by a detection alert in the last " +
                       str(WINDOW_DAYS) + " days."], summary=summary)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e))
