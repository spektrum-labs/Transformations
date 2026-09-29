# isscheduledscanningenabled.py - Rapid7 InsightCloudSec (Cloud Security, ff4fd43e)
#
# Method: listClouds. GET {serverUrl}/v2/public/clouds/list (also the status probe).
# Docs:   InsightCloudSec API v2, List Clouds ("List available configured clouds"); body shape
#         {"clouds": [{id, name, cloud_type_id, status, last_refreshed, ...}]} as in the community Go client
#         (github.com/gstotts/insightcloudsec, clouds.go CloudList / testdata listClouds.json). Harvest status
#         PAUSED is the documented pause (Resume Harvesting, /v2/public/clouds/status/set).
# Rule:   True when at least one cloud is connected and every cloud is not PAUSED and was harvested
#         (last_refreshed, UTC) within the last 48 hours.

import json
from datetime import datetime, timedelta


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        value = json.loads(text)
    return value


def envelope_error(value):
    """An Integration-Service or vendor error envelope, as text; None when the value is not one."""
    if not isinstance(value, dict):
        return None
    err = value.get("error")
    if err:
        return "API error: " + str(err)[:200]
    if str(value.get("status", "")).lower() == "error":
        return "API error: " + str(value.get("message") or value.get("detail") or "status Error")[:200]
    code = value.get("status_code", value.get("statusCode"))
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "API error: HTTP " + str(code)
    return None


def body_of(input, marker):
    """The vendor body: input["data"] (new TS format), then IS/TS envelopes, until marker(body) is true.
    Returns (body, None) or (None, reason)."""
    value = parse(input)
    if isinstance(input, dict) and "validation" in input and "data" in input:
        value = parse(input.get("data"))
    for depth in range(5):
        problem = envelope_error(value)
        if problem:
            return None, problem
        if marker(value):
            return value, None
        if not isinstance(value, dict):
            return None, "No InsightCloudSec response body"
        nxt = None
        for wrapper in ["apiResponse", "_response_data", "response", "result"]:
            if wrapper in value:
                nxt = parse(value.get(wrapper))
                break
        if nxt is None:
            return None, "Response is not the expected InsightCloudSec body"
        value = nxt
    return None, "Response is not the expected InsightCloudSec body"


def as_count(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def response(key, value, extra=None, errors=None, passes=None, fails=None):
    """errors -> dataCollection.status "error": Token-Service records the criterion Unevaluated."""
    out = {key: value}
    if extra:
        out.update(extra)
    return {
        "transformedResponse": out,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors or []},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": extra or {}},
            "evaluation": {"passReasons": passes or [], "failReasons": fails or [],
                           "recommendations": [], "additionalFindings": []},
            "metadata": {"transformationId": key, "vendor": "Rapid7", "product": "InsightCloudSec",
                         "category": "Cloud Security", "schemaVersion": "1.0",
                         "evaluatedAt": datetime.utcnow().isoformat() + "Z"},
        },
    }

WINDOW_HOURS = 48


def clouds_body(value):
    return isinstance(value, dict) and isinstance(value.get("clouds"), list)


def when(text):
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        stamp = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is not None:
        stamp = stamp.replace(tzinfo=None) - stamp.utcoffset()
    return stamp


def transform(input):
    """Every connected cloud account is being harvested on schedule (not paused, refreshed within 48 h).
    None (Unevaluated) on no data, an error, or a body without last_refreshed on any cloud."""
    key = "isScheduledScanningEnabled"
    try:
        body, problem = body_of(input, clouds_body)
        if problem:
            return response(key, None, errors=[problem])
        clouds = [c for c in body["clouds"] if isinstance(c, dict)]
        if not clouds:
            return response(key, False, {"cloudCount": 0}, fails=["No cloud account is connected to InsightCloudSec"])
        if not any("last_refreshed" in c for c in clouds):
            return response(key, None, errors=["No cloud in the response has a last_refreshed field"])
        cutoff = datetime.utcnow() - timedelta(hours=WINDOW_HOURS)
        stale = []
        for c in clouds:
            stamp = when(c.get("last_refreshed"))
            paused = str(c.get("status", "")).upper() == "PAUSED"
            if paused or stamp is None or stamp < cutoff:
                stale.append(str(c.get("name") or c.get("id")))
        extra = {"cloudCount": len(clouds), "staleOrPausedCloudCount": len(stale)}
        if stale:
            return response(key, False, extra, fails=[str(len(stale)) + " of " + str(len(clouds)) + " clouds are paused or not harvested in 48 h: " + ", ".join(stale[:10])])
        return response(key, True, extra, passes=["All " + str(len(clouds)) + " clouds were harvested in the last 48 h"])
    except Exception as e:
        return response(key, None, errors=["Transformation error: " + str(e)[:200]])
