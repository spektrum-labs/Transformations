"""
Transformation: isDASTScanCurrent
Vendor: PortSwigger Burp Suite DAST  |  Category: Application Security

Integration-Service method listCompletedScans: POST {serverUrl}/graphql/v1 with
  query CompletedScans($limit: Int) { scans(limit: $limit, sort_column: end, sort_order: desc,
  scan_status: [succeeded]) { id status start_time end_time ... scan_target { id name type } ... } }
  and variables {"limit": 100}.
Schema (portswigger.net/burp/extensibility/dast/graphql-api, read 2026-11-13): scans returns [Scan!];
Scan.status is a ScanStatus (queued, running, succeeded, cancelled, failed, paused); Scan.end_time is "the time
at which the scan finished", a Timestamp in ISO 8601 UTC with milliseconds.

True when a scan that succeeded finished within the last 30 days. daysSinceLastScan carries the number.
False when the successful-scan list was read and its newest scan finished more than 30 days ago, or the list is
empty (no successful scan visible to the API user). The list is sorted newest end first, so one page holds the
newest one.
Null (not evaluated) when the read failed (a GraphQL `errors` list, an error or refused answer, an empty or
unrecognised body, a null scans list), or, when no successful scan within 30 days was found, the read held a
scan of another status (the status filter was not applied) or a successful scan with no readable end time.
"""

import json
from datetime import datetime, timezone

VENDOR = "PortSwigger Burp Suite DAST"
CATEGORY = "Application Security"
# Integration-Service wraps a method response in one of these, and a GraphQL body is itself {"data": {...}}.
WRAPPERS = ("api_response", "response", "result", "apiResponse", "Output", "data")


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        if not value.strip():
            return None
        return json.loads(value)
    return value


def error_text(node):
    """Why a dict is an error answer rather than a GraphQL result, or None."""
    errors = node.get("errors")
    if isinstance(errors, list) and errors:
        first = errors[0]
        text = first.get("message") if isinstance(first, dict) else first
        return "Burp Suite DAST returned a GraphQL error: " + str(text)[:160]
    if node.get("error") is True or node.get("errorType") or (node.get("error") and not isinstance(node.get("error"), bool)):
        return "error answer: " + str(node.get("message") or node.get("error") or node.get("errorType"))[:160]
    for number in (node.get("statusCode"), node.get("status")):
        if isinstance(number, int) and not isinstance(number, bool) and number >= 400:
            return "HTTP " + str(number) + ": " + str(node.get("message") or "")[:160]
    if node.get("status") is False:
        return "the answer says status false: " + str(node.get("message") or "")[:160]
    return None


def find_list(data, field):
    """(items, problem): the GraphQL root field `field` (a list of objects) found under any wrapper, or why
    there is none. A GraphQL `errors` list fails the read even next to partial data."""
    node = parse(data)
    for depth in range(8):
        if not isinstance(node, dict):
            return None, "the response is empty or not a JSON object"
        problem = error_text(node)
        if problem:
            return None, problem
        if field in node:
            value = node[field]
            if not isinstance(value, list):
                return None, "the " + field + " list is missing or null"
            for item in value:
                if not isinstance(item, dict):
                    return None, "the " + field + " list holds an entry that is not an object"
            return value, None
        nxt = None
        for key in WRAPPERS:
            inner = node.get(key)
            if isinstance(inner, (str, bytes)):
                inner = parse(inner)
            if isinstance(inner, dict):
                nxt = inner
                break
        if nxt is None:
            break
        node = nxt
    if isinstance(node, dict) and (node.get("message") or node.get("detail")):
        return None, "vendor message: " + str(node.get("message") or node.get("detail"))[:160]
    return None, "no " + field + " list in the response"


def parse_time(value):
    """A Burp Suite DAST Timestamp (ISO 8601, UTC, milliseconds: 2026-11-08T14:35:12.190Z) as an aware
    datetime, or None when it is absent or unreadable."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    if "." in text:
        head, tail = text.split(".", 1)
        digits = ""
        rest = ""
        for pos in range(len(tail)):
            if tail[pos].isdigit():
                digits = digits + tail[pos]
            else:
                rest = tail[pos:]
                break
        text = head + "." + (digits[:6] if digits else "0") + rest
    try:
        stamp = datetime.fromisoformat(text)
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def days_ago(stamp, now):
    seconds = (now - stamp).total_seconds()
    if seconds < 0:
        return 0
    return int(seconds // 86400)


def label(obj):
    """A site, folder or scan target as people see it: its name, else its id."""
    if not isinstance(obj, dict):
        return "?"
    name = obj.get("name")
    if isinstance(name, str) and name.strip():
        return "'" + name.strip() + "'"
    return "id " + str(obj.get("id"))


def build_response(result, pass_reasons=None, fail_reasons=None, errors=None, summary=None,
                   recommendations=None, transform_id="", findings=None):
    errors = errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if errors else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "error" if errors else "success", "errors": errors,
                               "inputSummary": summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": findings or []},
            "metadata": {"evaluatedAt": datetime.now(timezone.utc).isoformat(), "schemaVersion": "1.0",
                         "transformationId": transform_id, "vendor": VENDOR, "category": CATEGORY},
        },
    }

KEY = "isDASTScanCurrent"
TRANSFORM_ID = "isdastscancurrent"
RECENT_DAYS = 30


def transform(input):
    try:
        scans, problem = find_list(input, "scans")
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=TRANSFORM_ID)
        now = datetime.now(timezone.utc)
        finished = []
        unreadable = 0
        other_status = 0
        for scan in scans:
            if scan.get("status") != "succeeded":
                other_status = other_status + 1
                continue
            ended = parse_time(scan.get("end_time"))
            if ended is None:
                unreadable = unreadable + 1
                continue
            finished.append((ended, scan))
        finished.sort(key=lambda pair: pair[0], reverse=True)
        result = {KEY: None, "daysSinceLastScan": None, "thresholdDays": RECENT_DAYS}
        summary = {"scansRead": len(scans), "succeededWithEndTime": len(finished), "unreadableEndTime": unreadable,
                   "otherStatus": other_status}
        if finished:
            result["daysSinceLastScan"] = days_ago(finished[0][0], now)
        if finished and result["daysSinceLastScan"] <= RECENT_DAYS:
            result[KEY] = True
            newest = finished[0][1]
            return build_response(result, pass_reasons=[
                "Last successful Burp Suite DAST scan finished " + str(result["daysSinceLastScan"]) + " day(s) ago (" +
                finished[0][0].isoformat()[:10] + ") on " + label(newest.get("scan_target"))],
                summary=summary, transform_id=TRANSFORM_ID)
        if other_status:
            return build_response(result, errors=[
                str(other_status) + " scan(s) in the read are not successful scans, so the read is not the "
                "successful-scan list this check needs"], summary=summary, transform_id=TRANSFORM_ID)
        if unreadable:
            return build_response(result, errors=[
                str(unreadable) + " successful scan(s) have no readable end time and no scan within " +
                str(RECENT_DAYS) + " days was found"], summary=summary, transform_id=TRANSFORM_ID)
        result[KEY] = False
        if finished:
            reason = ("The last successful Burp Suite DAST scan finished " + str(result["daysSinceLastScan"]) +
                      " day(s) ago (" + finished[0][0].isoformat()[:10] + ", " + label(finished[0][1].get("scan_target")) +
                      "), more than " + str(RECENT_DAYS))
        else:
            reason = "Burp Suite DAST has no successful scan visible to the API user"
        return build_response(result, fail_reasons=[reason], recommendations=[
            "Run a Burp Suite DAST scan of every site in scope at least every " + str(RECENT_DAYS) + " days, and "
            "make sure the API user's group can see those sites"], summary=summary, transform_id=TRANSFORM_ID)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)], transform_id=TRANSFORM_ID)
