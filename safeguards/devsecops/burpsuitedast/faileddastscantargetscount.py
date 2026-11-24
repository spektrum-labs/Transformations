"""
Transformation: failedDASTScanTargetsCount
Vendor: PortSwigger Burp Suite DAST  |  Category: Application Security

Integration-Service method listRecentScans: POST {serverUrl}/graphql/v1 with
  query RecentScans($limit: Int) { scans(limit: $limit, sort_column: start, sort_order: desc) { id status
  start_time end_time scan_target { id name type } schedule_item { id } scan_failure_code scan_failure_message } }
  and variables {"limit": 100}.
Schema (portswigger.net/burp/extensibility/dast/graphql-api, read 2026-11-13): ScanStatus is queued, running,
succeeded, cancelled, failed ("the scan was unable to start or was unable to finish due to errors") or paused;
scan_failure_message says why a scan failed.

Value: the number of scan targets whose most recent finished scan (succeeded, failed or cancelled; the newest by
start time) failed. Lower is better. Queued, running and paused scans have no outcome yet and are skipped; a
target whose latest finished scan was cancelled is not counted as failed and is reported. The reasons name the
failed targets with Burp's failure message.

Null (not evaluated), never 0: a GraphQL `errors` list, an error or refused answer, an empty or unrecognised body,
a null scans list; no finished scan in the read; a full page (100 scans, the most one read returns: a target whose
last finished scan started earlier is not in it, so the count could be short); a scan with an unknown status, or a
finished scan with no target id or no readable start time.
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

KEY = "failedDASTScanTargetsCount"
TRANSFORM_ID = "faileddastscantargetscount"
PAGE_LIMIT = 100
MAX_NAMED = 10
FINISHED = ("succeeded", "failed", "cancelled")
UNFINISHED = ("queued", "running", "paused")


def transform(input):
    try:
        scans, problem = find_list(input, "scans")
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=TRANSFORM_ID)
        if len(scans) >= PAGE_LIMIT:
            return build_response({KEY: None}, errors=[
                "The read holds the newest " + str(len(scans)) + " scans, the most one read returns; a site whose "
                "last finished scan started earlier is not in it, so the count could be short"],
                summary={"scansRead": len(scans)}, transform_id=TRANSFORM_ID)
        latest = {}
        for scan in scans:
            status = scan.get("status")
            if status in UNFINISHED:
                continue
            if status not in FINISHED:
                return build_response({KEY: None}, errors=["Scan id " + str(scan.get("id")) + " has an unknown status " +
                                                           str(status)[:40]], transform_id=TRANSFORM_ID)
            target = scan.get("scan_target")
            target_id = target.get("id") if isinstance(target, dict) else None
            if target_id is None or str(target_id).strip() == "":
                return build_response({KEY: None}, errors=["Scan id " + str(scan.get("id")) + " has no scan target id"],
                                      transform_id=TRANSFORM_ID)
            started = parse_time(scan.get("start_time"))
            if started is None:
                return build_response({KEY: None}, errors=["Scan id " + str(scan.get("id")) +
                                                           " has no readable start time"], transform_id=TRANSFORM_ID)
            known = latest.get(str(target_id))
            if known is None or started > known[0]:
                latest[str(target_id)] = (started, scan)
        if not latest:
            return build_response({KEY: None}, errors=[
                "No finished Burp Suite DAST scan is visible to the API user (" + str(len(scans)) +
                " queued, running or paused), so no outcome was measured"], transform_id=TRANSFORM_ID)
        failed = []
        cancelled = []
        for target_id in latest:
            started, scan = latest[target_id]
            entry = (started.isoformat()[:10], label(scan.get("scan_target")), scan)
            if scan.get("status") == "failed":
                failed.append(entry)
            elif scan.get("status") == "cancelled":
                cancelled.append(entry)
        failed.sort(key=lambda entry: entry[0], reverse=True)
        result = {KEY: len(failed), "scanTargetsAssessed": len(latest)}
        summary = {"scansRead": len(scans), "scanTargetsAssessed": len(latest), "failed": len(failed),
                   "cancelled": len(cancelled)}
        findings = []
        if cancelled:
            findings.append(str(len(cancelled)) + " target(s) whose latest finished scan was cancelled: " +
                            ", ".join([entry[1] for entry in cancelled[:MAX_NAMED]]))
        if failed:
            reasons = [str(len(failed)) + " of " + str(len(latest)) + " scan target(s) failed their latest finished scan"]
            for day, name, scan in failed[:MAX_NAMED]:
                message = scan.get("scan_failure_message")
                reasons.append(name + ": scan started " + day + " failed" +
                               (" (" + str(message)[:160] + ")" if message else ""))
            if len(failed) > MAX_NAMED:
                reasons.append(str(len(failed) - MAX_NAMED) + " more failed target(s)")
            return build_response(result, fail_reasons=reasons, recommendations=[
                "Fix what stops these Burp Suite DAST scans (Burp's failure message and remedy say why) and rerun "
                "them"], summary=summary, transform_id=TRANSFORM_ID, findings=findings)
        return build_response(result, pass_reasons=[
            "The latest finished scan of every one of the " + str(len(latest)) + " scan target(s) did not fail"],
            summary=summary, transform_id=TRANSFORM_ID, findings=findings)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)], transform_id=TRANSFORM_ID)
