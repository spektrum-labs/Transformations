"""Transformation: overdueCriticalHighVulnerabilitiesCount (CrowdStrike Falcon Spotlight, getCriticalVulnerabilities).

Vendor: CrowdStrike  |  Category: Endpoint Security
Integration: Crowdstrike - XDR Falcon (765f3eb2). The same input shape also comes from CrowdStrike MDR's
getCriticalVulnerabilities.

Input: getCriticalVulnerabilities, GET /spotlight/combined/vulnerabilities/v1 with the FQL filter
status:['open','reopen']+cve.severity:['CRITICAL','HIGH'] and facet=cve (without facet=cve a record carries no
cve.severity). IS pages it on meta.pagination.after (cursor, page size 5000, at most 20 pages), merges the pages
into `resources` and keeps meta.pagination with the vendor's `total` (`truncated` when maxPages stopped it).
One record is one vulnerability instance: one vulnerability on one host.

Numbers emitted (every file emits all three, its own key first, so each check's evidence shows all of them):
  openCriticalVulnerabilitiesCount         open or reopened instances with cve.severity CRITICAL
  openHighSeverityVulnerabilitiesCount     open or reopened instances with cve.severity HIGH
  overdueCriticalHighVulnerabilitiesCount  of those, CRITICAL first detected (created_timestamp) more than 15 days
                                           ago or HIGH more than 30 days ago (CISA BOD 19-02 remediation windows,
                                           the same windows as the Defender and Action1 transforms for these keys)

Fail closed: anything that is not a complete Spotlight read returns all three keys as None with dataCollection
"error" (Unevaluated): no envelope, a vendor error, no resources list, no numeric meta.pagination.total, a
truncated merge, fewer or more records than total, a repeated record id, or a record without id, status,
cve.severity or a readable created_timestamp.

Measured zero: a successful response whose meta.pagination.total is explicitly 0 (an int, or the digit string "0"
as stored evidence renders it), with `resources` an empty list and no errors, is the vendor's own count for the
filter and is reported as 0 for all three keys. Only that exact shape reads 0; a missing, null or non-numeric total
stays Unevaluated.
"""
import json
from datetime import datetime

KEY = "overdueCriticalHighVulnerabilitiesCount"
KEY_CRITICAL = "openCriticalVulnerabilitiesCount"
KEY_HIGH = "openHighSeverityVulnerabilitiesCount"
KEY_OVERDUE = "overdueCriticalHighVulnerabilitiesCount"
CRITICAL_DAYS = 15
HIGH_DAYS = 30
OPEN_STATUSES = ["open", "reopen"]
RECOMMENDATION = ("Patch or mitigate the open critical vulnerabilities first detected more than 15 days ago and "
                  "high more than 30 days ago in Falcon Spotlight.")


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, bytes):
        try:
            input_data = input_data.decode("utf-8")
        except Exception:
            input_data = ""
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
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_err_list or transform_err_list) else "success",
                               "errors": api_err_list},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transform_err_list else "success", "errors": transform_err_list,
                               "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": KEY, "vendor": "CrowdStrike", "category": "Endpoint Security"},
        },
    }


def unevaluated_result():
    result = {KEY: None}
    for k in [KEY_CRITICAL, KEY_HIGH, KEY_OVERDUE]:
        result[k] = None
    return result


def unevaluated(problem, validation):
    return create_response(unevaluated_result(), validation, fail_reasons=[problem], api_errors=[problem],
                           recommendations=["Confirm the Falcon API client has Vulnerabilities: Read and that Falcon "
                                            "Spotlight is licensed and assessing hosts."])


def as_count(value):
    """A non-negative int from an int or a digit string (stored evidence stringifies numbers), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def is_true(value):
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


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
    if data.get("error"):
        return None, "The Spotlight call failed: " + str(data.get("message") or data.get("errorMessage") or "error")[:300]
    resources = data.get("resources")
    meta = data.get("meta")
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    if not isinstance(resources, list) or not isinstance(pagination, dict):
        return None, "The response is not a Spotlight vulnerabilities envelope (resources list and meta.pagination)."
    total = as_count(pagination.get("total"))
    if total is None:
        return None, "Spotlight meta.pagination.total is missing or not a count, so a complete read cannot be shown."
    if is_true(pagination.get("truncated")) or is_true(meta.get("truncated")) or is_true(data.get("truncated")):
        return None, ("Read stopped at the page limit (" + str(len(resources)) + " of " + str(total)
                      + " records); a partial read is not scored.")
    if len(resources) != total:
        return None, "Read " + str(len(resources)) + " of " + str(total) + " Spotlight records; a partial read is not scored."
    critical = 0
    high = 0
    overdue = 0
    seen_ids = {}
    hosts = {}
    for rec in resources:
        if not isinstance(rec, dict):
            return None, "A Spotlight record is not an object."
        rid = rec.get("id")
        status = rec.get("status")
        cve = rec.get("cve")
        severity = cve.get("severity") if isinstance(cve, dict) else None
        created = parse_created(rec.get("created_timestamp"))
        if not isinstance(rid, str) or not rid or not isinstance(status, str) or not isinstance(severity, str) \
                or created is None:
            return None, "A Spotlight record has no id, status, cve.severity or readable created_timestamp."
        if rid in seen_ids:
            return None, "Spotlight record " + rid[:40] + " appears twice in the merged pages; the read is not clean."
        seen_ids[rid] = True
        if status.strip().lower() not in OPEN_STATUSES:
            continue
        sev = severity.strip().upper()
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
    numbers = {
        KEY_CRITICAL: critical,
        KEY_HIGH: high,
        KEY_OVERDUE: overdue,
        "hostsWithOpenCriticalOrHigh": len(hosts),
        "spotlightRecordsRead": len(resources),
        "spotlightTotal": total,
    }
    return numbers, None


def transform(input):
    try:
        data, validation = extract_input(input)
        numbers, problem = measure(data, datetime.utcnow())
        if problem:
            return unevaluated(problem, validation)
        result = {KEY: numbers[KEY]}
        for k in numbers:
            if k != KEY:
                result[k] = numbers[k]
        summary = ("Spotlight, all pages (" + str(numbers["spotlightRecordsRead"]) + " of " + str(numbers["spotlightTotal"])
                   + " open/reopened critical+high instances on " + str(numbers["hostsWithOpenCriticalOrHigh"])
                   + " hosts): " + str(numbers[KEY_CRITICAL]) + " critical, " + str(numbers[KEY_HIGH]) + " high, "
                   + str(numbers[KEY_OVERDUE]) + " past the BOD 19-02 window (critical > 15 days, high > 30 days).")
        passes = []
        fails = []
        recs = []
        if numbers[KEY] == 0:
            passes.append(summary)
        else:
            fails.append(summary)
            recs.append(RECOMMENDATION)
        return create_response(result, validation, pass_reasons=passes, fail_reasons=fails, recommendations=recs,
                               input_summary=numbers)
    except Exception as e:
        return create_response(unevaluated_result(), {"status": "error", "errors": [], "warnings": []},
                               fail_reasons=["Transformation error: " + str(e)[:300]],
                               transformation_errors=[str(e)[:300]])
