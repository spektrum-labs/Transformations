"""Transformation: openHighSeverityVulnerabilitiesCount (SentinelOne Singularity Vulnerability Management, method getApplicationRisks).

Vendor: SentinelOne  |  Category: Endpoint Security  |  Integration: SentinelOne (2bc425fa)
Same keys and meaning as safeguards/epp/crowdstrike-falcon/*FromSpotlight.py and
safeguards/7BC425FA-0638-4BF1-8194-19E7E4F2F43C/microsoft_endpoint_vulnerabilities.py, so bundles compare
SentinelOne, Falcon and Defender tenants the same way.

Input: getApplicationRisks, GET /web/api/v2.1/application-management/risks scoped like getEndpoints, paged by
IS on pagination.nextCursor (cursor), pages merged into `data`, the first page's pagination block kept
(totalItems; `truncated` when maxPages stopped it). One record is one CVE on one endpoint for one installed
application (public schema: cveId, severity, endpointId, detectionDate, mitigationStatus, daysDetected; the
snake_case spellings are accepted too). Records are de-duplicated on (endpointId, cveId), keeping the earliest
detectionDate, so one counted instance is one CVE on one endpoint -- the Falcon Spotlight unit.

Numbers emitted (every file emits all three, its own key first):
  openCriticalVulnerabilitiesCount         instances with severity Critical
  openHighSeverityVulnerabilitiesCount     instances with severity High
  overdueCriticalHighVulnerabilitiesCount  of those, Critical first detected more than 15 days ago or High more
                                           than 30 days ago (CISA BOD 19-02 windows, as for Falcon and Defender)
A record whose mitigation status says fixed, resolved, remediated or patched is not open. Any other status
(including an acknowledged risk) is still open.

Fail closed: anything that is not a complete risks read returns all three keys as None with dataCollection
"error" (Unevaluated): no envelope, a vendor error (an unlicensed tenant or a role without the
Application Management permission answers 403), no data list, no pagination block, a non-numeric totalItems,
a nextCursor left, a truncated merge, fewer records than totalItems, an EMPTY risk list (a tenant without the
Vulnerability Management licence can answer an empty list, so empty is not a measured zero), or a record
without a severity -- or, for a Critical/High record, without endpointId, cveId or a readable detectionDate.
"""
import json
from datetime import datetime, timedelta

KEY = "openHighSeverityVulnerabilitiesCount"
KEY_CRITICAL = "openCriticalVulnerabilitiesCount"
KEY_HIGH = "openHighSeverityVulnerabilitiesCount"
KEY_OVERDUE = "overdueCriticalHighVulnerabilitiesCount"
CRITICAL_DAYS = 15
HIGH_DAYS = 30
CLOSED_STATUSES = ["fixed", "resolved", "remediated", "patched"]
META = {"transformationId": KEY, "vendor": "SentinelOne", "category": "epp"}


def parse(value):
    if isinstance(value, bytes):
        value = value.decode("utf-8")
    if isinstance(value, str):
        text = value.strip()
        return json.loads(text) if text else None
    return value


def pick(record, names):
    for n in names:
        if n in record and record.get(n) not in (None, "", "None", "null"):
            return record.get(n)
    return None


def find_risk_list(obj):
    """(records, pagination, error) from the getApplicationRisks response, whatever wrapper arrives."""
    cur = obj
    for depth in range(6):
        try:
            cur = parse(cur)
        except Exception:
            return None, None, None
        if isinstance(cur, list):
            return None, None, None
        if not isinstance(cur, dict):
            return None, None, None
        if cur.get("errors") or cur.get("error") is True:
            detail = cur.get("errors") or cur.get("message") or cur.get("errorMessage") or "error"
            return None, None, json.dumps(detail)[:300]
        status = cur.get("statusCode") or cur.get("status_code")
        if isinstance(status, int) and status >= 400:
            return None, None, "HTTP " + str(status)
        if isinstance(cur.get("data"), list):
            pagination = cur.get("pagination")
            return cur["data"], (pagination if isinstance(pagination, dict) else None), None
        nxt = None
        for key in ["data", "result", "response", "apiResponse", "api_response", "_response_data", "Output"]:
            if isinstance(cur.get(key), (dict, str, bytes)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None, None
        cur = nxt
    return None, None, None


def to_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def parse_when(value):
    try:
        # strptime imports _strptime, which the Token-Service sandbox refuses.
        return datetime.fromisoformat(str(value)[:19])
    except Exception:
        return None


def complete_read(raw):
    records, pagination, error = find_risk_list(raw)
    if error is not None:
        return None, "SentinelOne returned an error instead of the application risks list: " + error
    if records is None:
        return None, "No SentinelOne application risks list in the response; nothing to evaluate."
    if pagination is None:
        return None, "The risks list carries no pagination block, so a complete read cannot be shown."
    total = to_count(pagination.get("totalItems"))
    if total is None or total < 0:
        return None, "pagination.totalItems is missing or not a whole number, so a complete read cannot be shown."
    records = [r for r in records if isinstance(r, dict)]
    if pagination.get("truncated") is True or str(pagination.get("truncated")).lower() == "true":
        return None, "Read stopped at the page limit (" + str(len(records)) + " of " + str(total) + "); a partial read is not counted."
    if str(pagination.get("nextCursor") or "").strip() not in ("", "None", "null"):
        return None, "More pages remain (nextCursor present); a partial read is not counted."
    if len(records) < total:
        return None, "Read " + str(len(records)) + " of " + str(total) + " risk records; a partial read is not counted."
    if not records:
        return None, ("SentinelOne returned no application risks. A tenant without the Vulnerability Management "
                      "licence can answer an empty list, so this is not a measured zero.")
    return records, None


def unevaluated(problem, validation=None):
    return respond({KEY: None, KEY_CRITICAL: None, KEY_HIGH: None, KEY_OVERDUE: None}, problem=problem)


def respond(result, problem=None, pass_reasons=None, fail_reasons=None, findings=None, summary=None):
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
                "additionalFindings": findings or [],
            },
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": META["transformationId"], "vendor": META["vendor"],
                         "category": META["category"]},
        },
    }


def transform(input):
    try:
        raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
        records, problem = complete_read(raw)
        if problem:
            return unevaluated(problem)
        now = datetime.utcnow()
        instances = {}
        closed = 0
        for r in records:
            severity = str(pick(r, ["severity", "cveSeverity", "cve_severity"]) or "").strip().lower()
            if not severity:
                return unevaluated("A risk record has no severity, so the counts cannot be trusted.")
            status = str(pick(r, ["mitigationStatus", "mitigation_status", "status"]) or "").strip().lower()
            if status in CLOSED_STATUSES:
                closed = closed + 1
                continue
            if severity not in ("critical", "high"):
                continue
            endpoint = pick(r, ["endpointId", "endpoint_id", "agentId", "agent_id"])
            cve = pick(r, ["cveId", "cve_id"])
            when = parse_when(pick(r, ["detectionDate", "detection_date"]))
            if endpoint is None or cve is None or when is None:
                return unevaluated("A " + severity + " risk record lacks endpointId, cveId or a readable detectionDate.")
            ident = str(endpoint) + "|" + str(cve).upper()
            prior = instances.get(ident)
            if prior is None or when < prior[1]:
                instances[ident] = (severity, when)
        critical = 0
        high = 0
        overdue = 0
        for ident in instances:
            severity, when = instances[ident]
            age = now - when
            if severity == "critical":
                critical = critical + 1
                if age > timedelta(days=CRITICAL_DAYS):
                    overdue = overdue + 1
            else:
                high = high + 1
                if age > timedelta(days=HIGH_DAYS):
                    overdue = overdue + 1
        counts = {KEY_CRITICAL: critical, KEY_HIGH: high, KEY_OVERDUE: overdue}
        result = {KEY: counts[KEY]}
        for k in counts:
            result[k] = counts[k]
        result["riskRecordsRead"] = len(records)
        line = (str(critical) + " open critical and " + str(high) + " open high CVE-on-endpoint instances; " +
                str(overdue) + " past the 15/30-day window (" + str(len(records)) + " risk records read, " +
                str(closed) + " marked fixed)")
        summary = {"riskRecordsRead": len(records), "closedRecords": closed, "criticalHighInstances": len(instances)}
        if counts[KEY] == 0:
            return respond(result, pass_reasons=[line], summary=summary)
        return respond(result, fail_reasons=[line], summary=summary)
    except Exception as e:
        return unevaluated("Transformation error: " + str(e))
