"""Transformation: openHighSeverityVulnerabilitiesCount (SentinelOne Singularity Vulnerability Management, vendor counts).

Vendor: SentinelOne  |  Category: Endpoint Security  |  Integration: SentinelOne (2bc425fa)
Same keys as safeguards/epp/crowdstrike-falcon/*FromSpotlightCounts.py and
safeguards/7BC425FA-0638-4BF1-8194-19E7E4F2F43C/microsoft_endpoint_vulnerabilities.py; the unit differs: one
SentinelOne application risk row (CVE x endpoint x application), so a count is at least SentinelOne's own
CVE-on-endpoint count (one row per affected application) and is not directly comparable with Falcon/Defender totals.

WHY COUNTS AND NOT ROWS. The earlier version paged every row of GET /web/api/v2.1/application-management/risks
(1000 per page, at most 50 pages). Large tenants hold several hundred thousand rows, so the read stopped at the page
cap and all three keys were Unevaluated. SentinelOne answers the question itself: the same endpoint with
countOnly=true returns pagination.totalItems for the filter, over the whole scope, without rows.

Input: the getApplicationRiskCounts workflow output, one block per step (IS merge + output.key), each the vendor body
{"data": [...], "pagination": {"totalItems": N, ...}} of GET .../application-management/risks?<scope>&countOnly=true:
  allRisks         no severity filter (every risk row in scope)
  critical         severities=CRITICAL
  high             severities=HIGH
  overdueCritical  severities=CRITICAL&detectionDate__lt={$utcNow-15d}
  overdueHigh      severities=HIGH&detectionDate__lt={$utcNow-30d}
(IS's {$utcNow-Nd} is the call time minus N days, RFC 3339 UTC.) One row is one CVE on one endpoint for one
installed application, so a count is a number of those rows.

Numbers emitted (every file emits all three, its own key first):
  openCriticalVulnerabilitiesCount         critical total
  openHighSeverityVulnerabilitiesCount     high total
  overdueCriticalHighVulnerabilitiesCount  overdueCritical + overdueHigh (CISA BOD 19-02 windows: critical first
                                           detected more than 15 days ago, high more than 30 days ago)
Status: the counts take every row SentinelOne lists for the severity. No status filter is applied (none is verified
for this endpoint), so a row the vendor still lists after a fix would be counted. That can only raise a count, never
turn a failing tenant into a passing one.

Fail closed: anything that is not five complete, consistent vendor counts returns all three keys as None with
dataCollection "error" (Unevaluated): no envelope, an IS or vendor error (an unlicensed tenant or a role without the
Application Management permission answers 403), a missing block, a block without a whole-number
pagination.totalItems, an allRisks total of 0 (a tenant without the Vulnerability Management licence can answer an
empty list, so zero rows is not a measured zero), or counts that disagree: critical + high above allRisks (a
severity filter the vendor ignored), or an overdue count above its open count (a date filter that widened the set).
"""
import json
from datetime import datetime

KEY = "openHighSeverityVulnerabilitiesCount"
KEY_CRITICAL = "openCriticalVulnerabilitiesCount"
KEY_HIGH = "openHighSeverityVulnerabilitiesCount"
KEY_OVERDUE = "overdueCriticalHighVulnerabilitiesCount"
BLOCKS = ["allRisks", "critical", "high", "overdueCritical", "overdueHigh"]
WRAPPERS = ["data", "result", "response", "apiResponse", "api_response", "_response_data", "Output"]
META = {"transformationId": KEY, "vendor": "SentinelOne", "category": "epp"}


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        return json.loads(text) if text else None
    return value


def error_of(obj):
    """The error a wrapper or vendor body reports, or None."""
    error = obj.get("error")
    if obj.get("errors") or error is True or obj.get("stepError") is True or (isinstance(error, str) and error.strip()):
        inner = obj.get("apiResponse")
        inner_message = inner.get("errorMessage") if isinstance(inner, dict) else None
        return json.dumps(obj.get("errors") or obj.get("message") or obj.get("errorMessage")
                          or (error if isinstance(error, str) else None) or inner_message or "error")[:300]
    status = obj.get("statusCode") or obj.get("status_code")
    if isinstance(status, str) and status.strip().isdigit():
        status = int(status.strip())
    if isinstance(status, int) and not isinstance(status, bool) and status >= 400:
        return "HTTP " + str(status)
    if str(obj.get("status") or "").strip().lower() in ("error", "failed"):
        return "status " + str(obj.get("status"))
    return None


def descend(obj, done):
    """(dict, error): the first dict under the usual wrappers for which done(dict) holds; (None, None) if none."""
    cur = obj
    for depth in range(6):
        try:
            cur = parse(cur)
        except Exception:
            return None, None
        if not isinstance(cur, dict):
            return None, None
        error = error_of(cur)
        if error is not None:
            return None, error
        if done(cur):
            return cur, None
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str, bytes)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def has_block(obj):
    return any(name in obj for name in BLOCKS)


def has_pagination(obj):
    return "pagination" in obj


def to_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def block_total(name, block):
    """(total, None) for one vendor count, or (None, problem)."""
    body, error = descend(block, has_pagination)
    if error is not None:
        return None, "SentinelOne returned an error for the " + name + " risk count: " + error
    if body is None:
        return None, "The " + name + " risk count is missing; the workflow did not deliver every count."
    pagination = body.get("pagination")
    total = to_count(pagination.get("totalItems")) if isinstance(pagination, dict) else None
    if total is None:
        return None, "The " + name + " risk count has no whole-number pagination.totalItems; nothing was measured."
    return total, None


def measure(raw):
    """(totals, None) for five complete, consistent counts, or (None, problem)."""
    blocks, error = descend(raw, has_block)
    if error is not None:
        return None, "SentinelOne returned an error instead of the application risk counts: " + error
    if blocks is None:
        return None, "No SentinelOne application risk counts in the response; nothing to evaluate."
    totals = {}
    for name in BLOCKS:
        total, problem = block_total(name, blocks.get(name))
        if problem:
            return None, problem
        totals[name] = total
    if totals["allRisks"] == 0:
        return None, ("SentinelOne reports no application risks. A tenant without the Vulnerability Management "
                      "licence can answer an empty list, so this is not a measured zero.")
    if totals["critical"] + totals["high"] > totals["allRisks"]:
        return None, ("SentinelOne counts disagree: " + str(totals["critical"]) + " critical + " + str(totals["high"])
                      + " high is more than the " + str(totals["allRisks"]) + " risks in scope; not scored.")
    if totals["overdueCritical"] > totals["critical"] or totals["overdueHigh"] > totals["high"]:
        return None, "SentinelOne counts disagree: an overdue count exceeds its open count; not scored."
    return totals, None


def unevaluated(problem):
    return respond({KEY: None, KEY_CRITICAL: None, KEY_HIGH: None, KEY_OVERDUE: None}, problem=problem)


def respond(result, problem=None, pass_reasons=None, fail_reasons=None, summary=None):
    ordered = {KEY: result.get(KEY)}
    for k in result:
        if k != KEY:
            ordered[k] = result[k]
    errors = [problem] if problem else []
    return {
        "transformedResponse": ordered,
        "additionalInfo": {
            "dataCollection": {"status": "error" if problem else "success", "errors": errors},
            "validation": {"status": "unknown", "errors": [], "warnings": []},
            "transformation": {"status": "success", "errors": [], "inputSummary": summary or {}},
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": (fail_reasons or []) + errors,
                "recommendations": [] if problem or not fail_reasons else [
                    "Patch or remove the vulnerable applications, critical first; clear critical findings older than "
                    "15 days and high older than 30 days."],
                "additionalFindings": [],
            },
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": META["transformationId"], "vendor": META["vendor"],
                         "category": META["category"]},
        },
    }


def transform(input):
    try:
        raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
        totals, problem = measure(raw)
        if problem:
            return unevaluated(problem)
        counts = {KEY_CRITICAL: totals["critical"], KEY_HIGH: totals["high"],
                  KEY_OVERDUE: totals["overdueCritical"] + totals["overdueHigh"]}
        line = (str(counts[KEY_CRITICAL]) + " critical and " + str(counts[KEY_HIGH]) + " high application risks; "
                + str(counts[KEY_OVERDUE]) + " past the window (" + str(totals["overdueCritical"])
                + " critical > 15 days, " + str(totals["overdueHigh"]) + " high > 30 days), from SentinelOne's counts "
                + "over " + str(totals["allRisks"]) + " risks in scope")
        if counts[KEY] == 0:
            return respond(counts, pass_reasons=[line], summary=totals)
        return respond(counts, fail_reasons=[line], summary=totals)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e))
