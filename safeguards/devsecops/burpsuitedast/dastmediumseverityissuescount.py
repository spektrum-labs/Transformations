"""
Transformation: dastMediumSeverityIssuesCount
Vendor: PortSwigger Burp Suite DAST  |  Category: Application Security

Integration-Service method listCompletedScans: POST {serverUrl}/graphql/v1 with
  query CompletedScans($limit: Int) { scans(limit: $limit, sort_column: end, sort_order: desc,
  scan_status: [succeeded]) { id status start_time end_time ... scan_target { id name type } ...
  issue_counts { total high { total certain firm tentative } medium { ... } low { ... } info { total } } ... } }
  and variables {"limit": 100}.
Schema (portswigger.net/burp/extensibility/dast/graphql-api, read 2026-11-13): Scan.issue_counts is IssueCounts,
"the number of issues found, sorted by their severity level"; IssueCounts.medium is CountsByConfidence, whose total is
the number of medium-severity issues the scan found at any confidence (certain, firm, tentative).
Scan.scan_target is the site (or CI-driven site) the scan ran against.

Value: the sum, over every scan target, of issue_counts.medium.total in that target's most recent successful scan.
Each target's newest successful scan stands for what is open on it now; older scans of the same target are not
added. Lower is better. The reasons name the targets that carry medium-severity issues.

UNVERIFIED (no real server read yet): the schema does not say whether issue_counts leaves out issues marked as
false positives or accepted risks, so the count may include them.

Null (not evaluated), never 0: a GraphQL `errors` list, an error or refused answer, an empty or unrecognised body,
a null scans list; an empty list (no successful scan, so nothing was measured); a full page (100 scans, the most
one read returns: a target whose last successful scan is older is not in it, so the sum could be short); a scan
of another status, or a scan with no target id, no readable end time or no readable medium count.
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

KEY = "dastMediumSeverityIssuesCount"
TRANSFORM_ID = "dastmediumseverityissuescount"
SEVERITY = "medium"
PAGE_LIMIT = 100
MAX_NAMED = 10


def count_of(scan):
    """issue_counts.<severity> of one scan as (total, certain, firm, tentative), or None when unreadable."""
    counts = scan.get("issue_counts")
    band = counts.get(SEVERITY) if isinstance(counts, dict) else None
    if not isinstance(band, dict):
        return None
    values = []
    for field in ("total", "certain", "firm", "tentative"):
        value = band.get(field)
        if field == "total" and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            return None
        values.append(value if isinstance(value, int) and not isinstance(value, bool) else 0)
    return values


def transform(input):
    try:
        scans, problem = find_list(input, "scans")
        if problem:
            return build_response({KEY: None}, errors=[problem], transform_id=TRANSFORM_ID)
        if not scans:
            return build_response({KEY: None}, errors=[
                "Burp Suite DAST has no successful scan visible to the API user, so there is no issue count to "
                "report"], transform_id=TRANSFORM_ID)
        if len(scans) >= PAGE_LIMIT:
            return build_response({KEY: None}, errors=[
                "The read holds the newest " + str(len(scans)) + " successful scans, the most one read returns; a "
                "site whose last successful scan is older is not in it, so the count could be short"],
                summary={"scansRead": len(scans)}, transform_id=TRANSFORM_ID)
        latest = {}
        for scan in scans:
            if scan.get("status") != "succeeded":
                return build_response({KEY: None}, errors=[
                    "A scan in the read is not a successful scan (status " + str(scan.get("status"))[:40] +
                    "), so the read is not the successful-scan list this count needs"], transform_id=TRANSFORM_ID)
            target = scan.get("scan_target")
            target_id = target.get("id") if isinstance(target, dict) else None
            if target_id is None or str(target_id).strip() == "":
                return build_response({KEY: None}, errors=["Scan id " + str(scan.get("id")) + " has no scan target id"],
                                      transform_id=TRANSFORM_ID)
            ended = parse_time(scan.get("end_time"))
            if ended is None:
                return build_response({KEY: None}, errors=["Scan id " + str(scan.get("id")) +
                                                           " has no readable end time"], transform_id=TRANSFORM_ID)
            known = latest.get(str(target_id))
            if known is None or ended > known[0]:
                latest[str(target_id)] = (ended, scan)
        total = 0
        certain = 0
        affected = []
        for target_id in latest:
            ended, scan = latest[target_id]
            values = count_of(scan)
            if values is None:
                return build_response({KEY: None}, errors=[
                    "Scan id " + str(scan.get("id")) + " has no readable issue_counts." + SEVERITY + ".total"],
                    transform_id=TRANSFORM_ID)
            total = total + values[0]
            certain = certain + values[1]
            if values[0] > 0:
                affected.append((values[0], label(scan.get("scan_target")), ended.isoformat()[:10]))
        affected.sort(key=lambda entry: entry[0], reverse=True)
        summary = {"scansRead": len(scans), "scanTargetsAssessed": len(latest), KEY: total,
                   "certainConfidence": certain}
        result = {KEY: total, "scanTargetsAssessed": len(latest)}
        if total > 0:
            reasons = [str(total) + " " + SEVERITY + "-severity issue(s) across the latest successful scans of " +
                       str(len(latest)) + " scan target(s)"]
            for count, name, day in affected[:MAX_NAMED]:
                reasons.append(name + ": " + str(count) + " in the scan that finished " + day)
            if len(affected) > MAX_NAMED:
                reasons.append(str(len(affected) - MAX_NAMED) + " more target(s) with " + SEVERITY + "-severity issues")
            return build_response(result, fail_reasons=reasons, recommendations=[
                "Fix or triage the " + SEVERITY + "-severity issues Burp Suite DAST reports, then rescan the sites "
                "to confirm"], summary=summary, transform_id=TRANSFORM_ID)
        return build_response(result, pass_reasons=[
            "No " + SEVERITY + "-severity issues in the latest successful scan of any of the " + str(len(latest)) +
            " scan target(s)"], summary=summary, transform_id=TRANSFORM_ID)
    except Exception as error:
        return build_response({KEY: None}, errors=[str(error)], transform_id=TRANSFORM_ID)
