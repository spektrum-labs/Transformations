# isiacmisconfigscanningenabled.py - Rapid7 InsightCloudSec (Cloud Security, ff4fd43e)
#
# Method: listIacScans. GET {serverUrl}/v3/iac/scans.
# Docs:   InsightCloudSec API v3, Get all IaC scan results ("Retrieves the results for all completed IaC scans"):
#         {page, total_pages, total_count, data[{id, status, scan_type, iac_provider, create_time, ...}]}.
# Rule:   True when at least one completed IaC scan was created in the last 30 days. False when there are no
#         scans, or every scan was read and the newest is older. None when only part of the list was read and
#         none of it is recent (the newest may be on an unread page).

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

WINDOW_DAYS = 30


def scans_body(value):
    return isinstance(value, dict) and isinstance(value.get("data"), list) and "total_count" in value


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
    """At least one IaC misconfiguration scan in the last 30 days."""
    key = "isIaCMisconfigScanningEnabled"
    try:
        body, problem = body_of(input, scans_body)
        if problem:
            return response(key, None, errors=[problem])
        total = as_count(body.get("total_count"))
        if total is None:
            return response(key, None, errors=["IaC scan list has no total_count"])
        scans = [s for s in body["data"] if isinstance(s, dict)]
        if total == 0:
            return response(key, False, {"iacScanCount": 0}, fails=["No IaC scan has been run in InsightCloudSec"])
        cutoff = datetime.utcnow() - timedelta(days=WINDOW_DAYS)
        stamps = [when(s.get("create_time")) for s in scans]
        dated = [t for t in stamps if t is not None]
        newest = max(dated) if dated else None
        extra = {"iacScanCount": total, "newestScan": newest.isoformat() if newest else None}
        if newest is not None and newest >= cutoff:
            return response(key, True, extra, passes=["Newest IaC scan " + newest.isoformat() + " is within 30 days"])
        if len(scans) >= total and len(dated) == len(scans):
            return response(key, False, extra, fails=["No IaC scan in the last 30 days"])
        return response(key, None, extra, errors=["Only part of the IaC scan list was read, and none of it is recent"])
    except Exception as e:
        return response(key, None, errors=["Transformation error: " + str(e)[:200]])
