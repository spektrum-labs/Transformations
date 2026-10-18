"""Transformation: isEDRDeployed (Rapid7 MDR / InsightIDR, method getHealthMetrics).

The Rapid7 Insight Agent is the endpoint sensor of Rapid7 MDR (InsightIDR endpoint detection and response).
Source: GET /idr/v1/health-metrics, the Insight Agent summary resource
(rrn:agents:<region>:<org>:status:summary) with online (seen in the last 10 minutes), offline (seen within
15 days), stale (not seen for 15+ days) and total counts.

True when at least one Insight Agent reported in the last 15 days (online + offline > 0). Breadth is a
separate key (requiredCoveragePercentage / isEndpointCoverageValid); this key answers "is the EDR sensor
deployed", the same convention as CrowdStrike Falcon isEDRDeployed. False when the summary is readable and
reports zero agents, or every deployed agent is stale.

Fail closed: isEDRDeployed=None (dataCollection error, never True) when the body is not a readable InsightIDR
health-metrics response, carries a vendor error, has no agent summary, or the counts are inconsistent.
"""
import json
from datetime import datetime, timedelta

KEY = "isEDRDeployed"


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


def transform(input):
    try:
        items, complete, problem = read_health(input)
        if problem:
            return unevaluated(problem)
        summaries = [i for i in items if i["rrn"].startswith("rrn:agents:")]
        if not summaries:
            return unevaluated("No Insight Agent summary (rrn:agents:...) in the health metrics; EDR deployment cannot be read.")
        s = summaries[0]
        online, offline, stale, total = to_int(s.get("online")), to_int(s.get("offline")), to_int(s.get("stale")), to_int(s.get("total"))
        if online is None or offline is None or total is None or online < 0 or offline < 0 or online + offline > total:
            return unevaluated("The Insight Agent summary has no consistent online/offline/total counts.")
        reporting = online + offline
        summary = {"agentsTotal": total, "agentsOnline": online, "agentsOffline": offline, "agentsStale": stale,
                   "agentsReporting": reporting}
        if total == 0:
            return respond(False, fail_reasons=["InsightIDR reports zero deployed Insight Agents: the Rapid7 EDR sensor is not deployed."],
                           summary=summary)
        if reporting == 0:
            return respond(False, fail_reasons=["All " + str(total) + " Insight Agents are stale (none reported in the last 15 days)."],
                           summary=summary)
        return respond(True, pass_reasons=[str(reporting) + " of " + str(total) + " Insight Agents reported in the last 15 days (" +
                       str(online) + " online, " + str(offline) + " offline, " + str(stale) + " stale)."], summary=summary)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e))
