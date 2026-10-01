"""Transformation: isCloudMonitoringEnabled (Rapid7 MDR / InsightIDR, method getLogsets).

True when an InsightIDR Cloud Service Activity or Cloud Service Admin Activity log set holds
at least one log (InsightIDR files cloud-service event sources, such as Microsoft 365, Azure, AWS,
Okta, into these log sets). This proves a cloud event source is configured; it does not read event freshness.

Fail closed: returns isCloudMonitoringEnabled=None (never True) when the body is not a readable InsightIDR
response, carries a vendor error, or does not hold enough evidence to decide.
"""
import json
from datetime import datetime, timedelta

KEY = "isCloudMonitoringEnabled"


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
        if not isinstance(value, dict) or "logsets" in value:
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

CLOUD_SETS = ["cloud service activity", "cloud service admin activity"]


def transform(input):
    try:
        data = envelope(input)
        if not isinstance(data, dict) or not isinstance(data.get("logsets"), list):
            return unevaluated("Not an InsightIDR /log_search/management/logsets body; nothing to evaluate.")
        if vendor_error(data):
            return unevaluated("InsightIDR returned an error body; nothing to evaluate.")
        sets = [s for s in data["logsets"] if isinstance(s, dict) and isinstance(s.get("name"), str)]
        if not sets:
            return unevaluated("InsightIDR returned no log sets; nothing to evaluate.")
        cloud = [s for s in sets if s["name"].strip().lower() in CLOUD_SETS]
        logs = 0
        for s in cloud:
            if isinstance(s.get("logs_info"), list):
                logs = logs + len(s["logs_info"])
        summary = {"logSets": len(sets), "cloudLogSets": len(cloud), "cloudServiceLogs": logs}
        if logs > 0:
            return respond(True, pass_reasons=[str(logs) + " logs are filed in the InsightIDR Cloud Service log sets, so cloud service event sources are configured."],
                           summary=summary)
        return respond(False, fail_reasons=["No log is filed in the InsightIDR Cloud Service Activity / Cloud Service Admin Activity log sets: no cloud service event source is configured."],
                       summary=summary)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e))
