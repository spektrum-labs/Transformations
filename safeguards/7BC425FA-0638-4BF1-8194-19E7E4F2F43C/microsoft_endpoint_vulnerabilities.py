"""Transformation: open and overdue Critical/High vulnerabilities (Windows Defender One-Click, every page read).

Vendor: Microsoft Defender for Endpoint (Defender Vulnerability Management)  |  Category: Endpoint Security
Criteria keys answered: openCriticalVulnerabilitiesCount, openHighSeverityVulnerabilitiesCount,
overdueCriticalHighVulnerabilitiesCount (same keys and meaning as safeguards/epp/crowdstrike-falcon/
isPatchManagementValid.py, so bundles compare Defender and Falcon tenants the same way).

Input: getSoftwareVulnerabilitiesByMachine, GET
https://api.securitycenter.microsoft.com/api/machines/SoftwareVulnerabilitiesByMachine (the "export software
vulnerabilities assessment" JSON API, application permission Vulnerability.Read.All on WindowsDefenderATP),
paged by IS on @odata.nextLink (pagination type "link", dataPath "value"). IS merges the pages into `value`.
Each record is one CVE on one device for one installed software version; the export lists what the device
carries now. Records are de-duplicated on (deviceId, cveId), keeping the earliest firstSeenTimestamp, so one
counted instance is one CVE on one device -- the Falcon Spotlight unit.

Numbers emitted (every key, so each check's evidence shows all of them):
  openCriticalVulnerabilitiesCount         CVE-on-device instances with vulnerabilitySeverityLevel Critical
  openHighSeverityVulnerabilitiesCount     CVE-on-device instances with vulnerabilitySeverityLevel High
  overdueCriticalHighVulnerabilitiesCount  of those, Critical first seen (firstSeenTimestamp) more than 15 days
                                           ago or High more than 30 days ago (CISA BOD 19-02 windows)

Fail closed: anything that is not a complete export read returns every count as None with dataCollection
"error" (Unevaluated): no envelope, a vendor error body, no `value` list, an @odata.nextLink still present
(IS stopped at maxPages or a page failed, so the merge is partial), a truncated marker, an empty export
(Defender Vulnerability Management has assessed nothing, which is not a measured zero), or a record without
a severity -- or, for a Critical/High record, without deviceId, cveId or a readable firstSeenTimestamp.
"""
import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('openCriticalVulnerabilitiesCount', 'openHighSeverityVulnerabilitiesCount', 'overdueCriticalHighVulnerabilitiesCount')


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)

KEY_CRITICAL = "openCriticalVulnerabilitiesCount"
KEY_HIGH = "openHighSeverityVulnerabilitiesCount"
KEY_OVERDUE = "overdueCriticalHighVulnerabilitiesCount"
CRITICAL_DAYS = 15
HIGH_DAYS = 30
CLOSED_STATUSES = ["fixed", "resolved", "remediated"]


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
            input_data = None
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
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
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if transform_err_list else "success", "errors": transform_err_list,
                               "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0",
                         "transformationId": "microsoft_endpoint_vulnerabilities",
                         "vendor": "Microsoft Defender for Endpoint", "category": "Endpoint Security"},
        },
    }


def unevaluated_result():
    return {KEY_CRITICAL: None, KEY_HIGH: None, KEY_OVERDUE: None}


def unevaluated(problem, validation):
    return create_response(unevaluated_result(), validation, fail_reasons=[problem], api_errors=[problem],
                           recommendations=["Confirm the One-Click app holds Vulnerability.Read.All (WindowsDefenderATP) "
                                            "with admin consent and that Defender Vulnerability Management is onboarded."])


def parse_seen(value):
    """'2026-09-01 12:00:00.1234567', '2026-09-01T12:00:00Z' or similar -> naive UTC datetime, or None."""
    if not isinstance(value, str) or len(value) < 19:
        return None
    text = value[:19].replace(" ", "T")
    try:
        return datetime.fromisoformat(text)
    except Exception:
        return None


def has_more_pages(data):
    link = data.get("@odata.nextLink")
    if isinstance(link, str) and link.strip():
        return True
    if data.get("truncated") is True:
        return True
    pagination = data.get("pagination")
    if isinstance(pagination, dict) and pagination.get("truncated") is True:
        return True
    return False


def measure(data, now):
    """Return (numbers, None) for a complete export read, or (None, problem)."""
    if not isinstance(data, dict):
        return None, "No Defender vulnerability export envelope; nothing to evaluate."
    if data.get("error") or data.get("errors"):
        err = data.get("error") or data.get("errors")
        return None, "Defender returned an error for the vulnerability export: " + json.dumps(err)[:300]
    records = data.get("value")
    if not isinstance(records, list):
        return None, "The response is not a Defender vulnerability export (no value list)."
    if has_more_pages(data):
        return None, ("Read " + str(len(records)) + " records but more pages remain (@odata.nextLink present); "
                      "a partial read is not scored.")
    if not records:
        return None, ("The vulnerability export is empty: Defender Vulnerability Management has assessed no devices, "
                      "which is not a measured zero.")
    instances = {}
    for rec in records:
        if not isinstance(rec, dict):
            return None, "A Defender vulnerability record is not an object."
        severity = rec.get("vulnerabilitySeverityLevel")
        if not isinstance(severity, str) or not severity.strip():
            return None, "A Defender vulnerability record has no vulnerabilitySeverityLevel."
        status = rec.get("status")
        if isinstance(status, str) and status.strip().lower() in CLOSED_STATUSES:
            continue
        sev = severity.strip().lower()
        if sev not in ["critical", "high"]:
            continue
        device = rec.get("deviceId")
        cve = rec.get("cveId")
        seen = parse_seen(rec.get("firstSeenTimestamp"))
        if not isinstance(device, str) or not device or not isinstance(cve, str) or not cve or seen is None:
            return None, "A Critical/High Defender record has no deviceId, cveId or readable firstSeenTimestamp."
        ident = device + "|" + cve
        prior = instances.get(ident)
        if prior is None or seen < prior["seen"]:
            instances[ident] = {"sev": sev, "seen": seen, "device": device, "cve": cve}
    critical = 0
    high = 0
    overdue = 0
    devices = {}
    cves = {}
    for ident in instances:
        inst = instances[ident]
        age_days = (now - inst["seen"]).days
        if inst["sev"] == "critical":
            critical = critical + 1
            if age_days > CRITICAL_DAYS:
                overdue = overdue + 1
        else:
            high = high + 1
            if age_days > HIGH_DAYS:
                overdue = overdue + 1
        devices[inst["device"]] = True
        cves[inst["cve"]] = True
    numbers = {
        KEY_CRITICAL: critical,
        KEY_HIGH: high,
        KEY_OVERDUE: overdue,
        "devicesWithOpenCriticalOrHigh": len(devices),
        "distinctOpenCriticalOrHighCves": len(cves),
        "vulnerabilityRecordsRead": len(records),
    }
    return numbers, None


def transform(input):
    try:
        data, validation = extract_input(input)
        numbers, problem = measure(data, datetime.utcnow())
        if problem:
            return unevaluated(problem, validation)
        summary = ("Defender Vulnerability Management export, all pages (" + str(numbers["vulnerabilityRecordsRead"])
                   + " records; open Critical/High on " + str(numbers["devicesWithOpenCriticalOrHigh"]) + " devices): "
                   + str(numbers[KEY_CRITICAL]) + " critical, " + str(numbers[KEY_HIGH]) + " high, "
                   + str(numbers[KEY_OVERDUE]) + " past the BOD 19-02 window (critical > 15 days, high > 30 days).")
        passes = []
        fails = []
        recs = []
        if numbers[KEY_OVERDUE] == 0:
            passes.append(summary)
        else:
            fails.append(summary)
            recs.append("Patch or mitigate the Critical vulnerabilities first seen more than 15 days ago and High more "
                        "than 30 days ago in Defender Vulnerability Management.")
        return create_response(dict(numbers), validation, pass_reasons=passes, fail_reasons=fails,
                               recommendations=recs, input_summary=numbers)
    except Exception as e:
        return create_response(unevaluated_result(), {"status": "error", "errors": [], "warnings": []},
                               fail_reasons=["Transformation error: " + str(e)],
                               transformation_errors=[str(e)])
