"""Transformation: isPatchManagementValid (CrowdStrike Falcon Spotlight, numbers read across every page).

Input: getSpotlightVulnerabilitiesCombined, GET /spotlight/combined/vulnerabilities/v1 with the FQL filter
status:['open','reopen']+cve.severity:['CRITICAL','HIGH'], paged by IS on meta.pagination.after (limit 5000). IS merges
the pages into `resources` and keeps page 1's meta.pagination (with `total`; `truncated` when maxPages stopped it).
One record is one vulnerability instance: one CVE on one host.

Numbers emitted (every key, so the evidence of each check shows all of them):
  openCriticalVulnerabilitiesCount       open or reopened instances with cve.severity CRITICAL
  openHighSeverityVulnerabilitiesCount   open or reopened instances with cve.severity HIGH
  overdueCriticalHighVulnerabilitiesCount  of those, CRITICAL first detected (created_timestamp) more than 15 days ago
                                         or HIGH more than 30 days ago (CISA BOD 19-02 remediation windows)
  isPatchManagementValid                 derived: true exactly when overdueCriticalHighVulnerabilitiesCount == 0

Fail closed: anything that is not a complete Spotlight read returns the key as None with dataCollection "error"
(Unevaluated): no envelope, vendor errors, no numeric meta.pagination.total, fewer records than total, a
truncated merge, or a record without status, severity or a readable created_timestamp.
Known limit: a Spotlight tenant with open/reopen critical/high total 0 reads 0 (a measured zero from the Spotlight API
envelope); Spotlight cannot tell us from this call how many hosts it assessed.
"""
import json
from datetime import datetime

KEY = "isPatchManagementValid"
CRITICAL_DAYS = 15
HIGH_DAYS = 30
OPEN_STATUSES = ["open", "reopen"]


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, str):
        try:
            input_data = json.loads(input_data)
        except Exception:
            input_data = {}
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for i in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": "CrowdStrike", "category": "Endpoint Security"},
        },
    }


def unevaluated(problem, validation):
    return create_response({KEY: None}, validation, fail_reasons=[problem], api_errors=[problem])


def parse_created(value):
    """ISO-8601 UTC ('2026-09-01T12:00:00Z', optional fraction) -> naive UTC datetime, or None."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    try:
        return datetime.fromisoformat(value[:19])
    except Exception:
        return None


def measure(data, now):
    """Return (numbers, None) for a complete Spotlight read, or (None, problem)."""
    if not isinstance(data, dict):
        return None, "No CrowdStrike Spotlight response envelope; nothing to evaluate."
    errors = data.get("errors")
    if errors:
        return None, "CrowdStrike Spotlight returned errors: " + json.dumps(errors)[:300]
    if data.get("error") is True:
        return None, "The Spotlight call failed: " + str(data.get("message") or data.get("errorMessage") or "error")[:300]
    resources = data.get("resources")
    meta = data.get("meta")
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    if not isinstance(resources, list) or not isinstance(pagination, dict):
        return None, "The response is not a Spotlight vulnerabilities envelope (resources list and meta.pagination)."
    total = pagination.get("total")
    if isinstance(total, bool) or not isinstance(total, int) or total < 0:
        return None, "Spotlight meta.pagination.total is missing, so a complete read cannot be shown."
    if pagination.get("truncated"):
        return None, "Read stopped at the page limit (" + str(len(resources)) + " of " + str(total) + "); a partial read is not scored."
    if len(resources) != total:
        return None, "Read " + str(len(resources)) + " of " + str(total) + " Spotlight records; a partial read is not scored."
    critical = 0
    high = 0
    overdue = 0
    hosts = {}
    cves = {}
    for rec in resources:
        if not isinstance(rec, dict):
            return None, "A Spotlight record is not an object."
        status = rec.get("status")
        cve = rec.get("cve")
        severity = cve.get("severity") if isinstance(cve, dict) else None
        created = parse_created(rec.get("created_timestamp"))
        if not isinstance(status, str) or not isinstance(severity, str) or created is None:
            return None, "A Spotlight record has no status, cve.severity or readable created_timestamp."
        if status.lower() not in OPEN_STATUSES:
            continue
        sev = severity.upper()
        age_days = (now - created).days
        if sev == "CRITICAL":
            critical = critical + 1
            if age_days > CRITICAL_DAYS:
                overdue = overdue + 1
        elif sev == "HIGH":
            high = high + 1
            if age_days > HIGH_DAYS:
                overdue = overdue + 1
        else:
            continue
        hosts[str(rec.get("aid") or "")] = True
        cves[str(cve.get("id") or "")] = True
    numbers = {
        "openCriticalVulnerabilitiesCount": critical,
        "openHighSeverityVulnerabilitiesCount": high,
        "overdueCriticalHighVulnerabilitiesCount": overdue,
        "isPatchManagementValid": overdue == 0,
        "hostsWithOpenCriticalOrHigh": len(hosts),
        "distinctOpenCriticalOrHighCves": len(cves),
        "spotlightRecordsRead": len(resources),
    }
    return numbers, None


def transform(input):
    data, validation = extract_input(input)
    numbers, problem = measure(data, datetime.utcnow())
    if problem:
        return unevaluated(problem, validation)
    result = {KEY: numbers[KEY]}
    for k in numbers:
        if k != KEY:
            result[k] = numbers[k]
    summary = ("Spotlight, all pages (" + str(numbers["spotlightRecordsRead"]) + " open/reopened critical+high instances on "
               + str(numbers["hostsWithOpenCriticalOrHigh"]) + " hosts): " + str(numbers["openCriticalVulnerabilitiesCount"])
               + " critical, " + str(numbers["openHighSeverityVulnerabilitiesCount"]) + " high, "
               + str(numbers["overdueCriticalHighVulnerabilitiesCount"]) + " past the BOD 19-02 window (critical > 15 days, high > 30 days).")
    passes = []
    fails = []
    recs = []
    if numbers["overdueCriticalHighVulnerabilitiesCount"] == 0:
        passes.append(summary)
    else:
        fails.append(summary)
        recs.append("Patch or mitigate the open critical vulnerabilities older than 15 days and high older than 30 days in Falcon Spotlight.")
    return create_response(result, validation, pass_reasons=passes, fail_reasons=fails, recommendations=recs,
                           input_summary=numbers)
