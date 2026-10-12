"""
Transformation: externalAssetInventoryCount
Vendor: Project Discovery (Nuclei, run by Spektrum)  |  Category: Attack Surface Management
Evaluates: Count of externally exposed hosts discovered for the passport domain (subfinder).

Input: the runParallelASMScan response the noCriticalFindings workflow already fetches (subfinder discovery of the
passport domain, then nuclei critical-severity templates across up to 25 discovered hosts). No extra scan.
Fails closed: a scan that did not complete, scanned zero hosts, or reports a failed host or an error returns
None with the reason in dataCollection.errors.
"""

import json
from datetime import datetime

#: The criteria this file answers. A None among them means "not measured", never "failed".
NONE_MEANS_NOT_EVALUATED = ('externalAssetInventoryCount',)


def criteria_unmeasured(result):
    """True when every criterion this file answers that the result carries is None.

    Token-Service grades a None criterion as FAILED unless additionalInfo.dataCollection.status
    is "error". The status is read per response, so it is set only when no criterion in the
    result was measured; marking a partly measured result would hide the measured ones.
    """
    present = [k for k in NONE_MEANS_NOT_EVALUATED if k in result]
    return len(present) > 0 and all(result[k] is None for k in present)


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for step in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None,
                    api_errors=None, additional_findings=None):
    # A None criterion was not measured. Token-Service grades None as FAILED unless
    # dataCollection.status is "error", which needs a non-empty api_errors, so carry the
    # reason across when the caller did not.
    if not api_errors and isinstance(result, dict) and criteria_unmeasured(result):
        api_errors = (list(fail_reasons or []) or list(transformation_errors or [])
                      or ["The response could not answer this check, so it was not evaluated."])
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", [])
            },
            "transformation": {
                "status": "error" if (transformation_errors or []) else "success",
                "errors": transformation_errors or [],
                "inputSummary": input_summary or {}
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or []
            },
            "metadata": {
                "evaluatedAt": datetime.utcnow().isoformat() + "Z",
                "schemaVersion": "1.0",
                "transformationId": "externalAssetInventoryCount",
                "vendor": "Project Discovery",
                "category": "Attack Surface Management"
            }
        }
    }


def to_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# --- scan reason ----------------------------------------------------------------------------------------
# The Integration Service answers a scan it has no result for as {"status": "error", "reason": "<code>",
# "message": ...}: asm_scan_in_progress (a scan is still running), asm_scan_retry_backoff (the last scan
# produced nothing usable, so no new scan was started), asm_scan_shared_no_result and
# asm_scan_max_duration_exceeded. The code is passed on as dataCollection.errorCode, so a reader can tell a scan
# that is still running from a broken integration. An error reply measured nothing, so the criterion is None
# (Not evaluated), never False, whatever the reason: an asm_scan_ code, any other code, no reason, or a reason
# that is not a plain code (that one is dropped, and the text stays generic).
SCAN_REASON_MAX_LENGTH = 60
SCAN_REASON_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789_"
SCAN_REASON_TEXT = {
    "asm_scan_in_progress": "the scan is still running; its result is read on the next evaluation",
    "asm_scan_retry_backoff": "the last scan produced no usable result, so a new scan has not started yet",
    "asm_scan_shared_no_result": "the scan that was already running produced no usable result",
    "asm_scan_max_duration_exceeded": "the scan ran past its time limit",
}


def scan_reason(data):
    """The reason code of a scan reply that is not a result: a plain lower-case code of at most 60 characters,
    else None (a successful scan, no reason, or a reason that is not a plain code)."""
    if not isinstance(data, dict) or data.get("status") == "success":
        return None
    reason = data.get("reason")
    if not isinstance(reason, str):
        return None
    reason = reason.strip().lower()
    if not reason or len(reason) > SCAN_REASON_MAX_LENGTH:
        return None
    for ch in reason:
        if ch not in SCAN_REASON_CHARS:
            return None
    return reason


def scan_status_problem(status, domain, reason):
    """The error text for a scan reply that is not a result."""
    if reason is None:
        return "Nuclei scan status: " + str(status) + " for " + str(domain)
    if reason.startswith("asm_scan_"):
        return ("Nuclei scan not evaluated (" + reason + "): "
                + SCAN_REASON_TEXT.get(reason, "the scan did not produce a result"))
    return "Nuclei scan status: " + str(status) + " (" + reason + ") for " + str(domain)


def with_error_code(response, error_code):
    """Label a reply with the reason code the Integration Service gave, when it gave one."""
    if error_code:
        response["additionalInfo"]["dataCollection"]["errorCode"] = error_code
    return response
# --- end scan reason -------------------------------------------------------------------------------------


def scan_problem(data):
    """None when the scan completed across at least one host with no failed host and no error; else the reason."""
    if not isinstance(data, dict):
        return "No scan data"
    domain = data.get("primaryDomain") or data.get("domain") or "unknown"
    status = data.get("status", "unknown")
    if status != "success":
        return scan_status_problem(status, domain, scan_reason(data))
    scanned = to_int(data.get("domainsScanned"))
    if scanned is None or scanned <= 0:
        return "Nuclei scanned zero hosts for " + str(domain)
    failed = [r.get("domain", "unknown") for r in (data.get("domainResults") or [])
              if isinstance(r, dict) and r.get("status") not in ("success", "unresponsive")]
    errors = data.get("errors") or []
    if failed or errors:
        return "Nuclei scan failed for " + str(max(len(failed), len(errors))) + " host(s) of " + str(domain)
    return None


def finding_severity(finding):
    info = finding.get("info") if isinstance(finding, dict) else None
    sev = info.get("severity") if isinstance(info, dict) else None
    if not sev and isinstance(finding, dict):
        sev = finding.get("severity")
    return str(sev or "").lower()


def finding_tags(finding):
    info = finding.get("info") if isinstance(finding, dict) else None
    tags = info.get("tags") if isinstance(info, dict) else None
    if isinstance(tags, str):
        tags = tags.split(",")
    if not isinstance(tags, list):
        return []
    return [str(t).strip().lower() for t in tags]


def finding_name(finding):
    info = finding.get("info") if isinstance(finding, dict) else None
    name = info.get("name") if isinstance(info, dict) else None
    return str(name or finding.get("template-id") or "Unknown") if isinstance(finding, dict) else "Unknown"


def transform(input):
    criteriaKey = "externalAssetInventoryCount"
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if validation.get("status") == "failed":
            reason = "Input validation failed: the scan response did not match its schema, so the count is unknown"
            return create_response(result={criteriaKey: None}, validation=validation, api_errors=[reason],
                                   fail_reasons=[reason])
        problem = scan_problem(data)
        domain = (data.get("primaryDomain") or data.get("domain") or "unknown") if isinstance(data, dict) else "unknown"
        summary = {"domain": domain,
                   "domainsScanned": to_int(data.get("domainsScanned")) if isinstance(data, dict) else None,
                   "templatesScanned": to_int(data.get("templatesScanned")) if isinstance(data, dict) else None}
        if problem:
            return with_error_code(
                create_response(result={criteriaKey: None}, validation=validation, api_errors=[problem],
                                fail_reasons=[problem], input_summary=summary),
                scan_reason(data))
        findings = [f for f in (data.get("findings") or []) if isinstance(f, dict)]
        discovered = to_int(data.get("totalDiscovered"))
        if discovered is None:
            discovered = to_int(data.get("domainsScanned"))
        if discovered is None or discovered <= 0:
            reason = "Scan reported no discovered hosts for " + str(domain)
            return create_response(result={criteriaKey: None}, validation=validation, api_errors=[reason],
                                   fail_reasons=[reason], input_summary=summary)
        return create_response(
            result={criteriaKey: discovered, "hostsScanned": to_int(data.get("domainsScanned")),
                    "inventoryCapped": bool(data.get("domainsCapped"))},
            validation=validation,
            pass_reasons=[str(discovered) + " external host(s) discovered for " + str(domain)],
            input_summary=summary)
    except Exception as e:
        reason = "Transformation error, so the count is unknown: " + str(e)
        return create_response(result={criteriaKey: None},
                               validation={"status": "error", "errors": [], "warnings": []},
                               api_errors=[reason], transformation_errors=[str(e)], fail_reasons=[reason])
