"""
Transformation: requiredCoveragePercentage
Vendor: ManageEngine Endpoint Central (Malware Protection / Next-Gen Antivirus add-on)  |  Category: EPP
Source: a two-step workflow merged under output keys
  computers  - GET /api/1.4/som/computers?pagelimit=1000 (Scope of Management computer list, scope Common.READ)
  edrDevices - GET /edr/api/view/devices?pageLimit=1000 (anti-malware device list, scope EDR.READ)

Value: a whole-number percentage, floor(100 * covered / in scope). in scope = computers whose Endpoint Central
agent is installed (installation_status 22) and whose agent_last_contact_time is within 15 days of the newest one
among them (endpoint rules 2026-09-29; the rest are reported as staleComputerCount). covered = in-scope computers
that appear in the anti-malware device list (matched on resource_id) with protection running (status 1 active or
11 quarantined). An in-scope computer missing from that list, or listed as 0 not enabled / 8 inactive, is not
covered. The management agent alone is not endpoint protection, so it never counts as coverage by itself.
Computers whose agent is not installed are reported as agentNotInstalledCount. The pass bar lives in the
requirement.

Not evaluated (requiredCoveragePercentage None, dataCollection "error"): either read missing or failed, either
list truncated (total above the rows returned, or another page), no device carrying the anti-malware component
(this tool cannot speak for the fleet), no installed computer inside the window, or an in-scope computer whose
anti-malware status is not one of the documented codes (0, 1, 8, 11).
"""
import json
from datetime import datetime

CRITERIA_KEY = "requiredCoveragePercentage"
WINDOW_MS = 15 * 24 * 60 * 60 * 1000
STATUS_NAMES = {
    "0": "not_enabled", "not enabled": "not_enabled", "yet to enable": "not_enabled", "yet_to_enable": "not_enabled",
    "1": "active", "active": "active",
    "8": "inactive", "inactive": "inactive",
    "11": "quarantined", "quarantined": "quarantined",
}
WRAPPERS = ["api_response", "response", "result", "apiResponse", "Output"]


def parse_input(input_data):
    if isinstance(input_data, bytes):
        input_data = input_data.decode("utf-8")
    if isinstance(input_data, str):
        input_data = json.loads(input_data)
    return input_data


def extract_input(input_data):
    validation = {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}
    data = input_data
    if isinstance(data, dict) and "data" in data and "validation" in data:
        validation = data["validation"] if isinstance(data["validation"], dict) else validation
        data = data["data"]
    for step in range(3):
        if not isinstance(data, dict):
            break
        moved = False
        for key in WRAPPERS:
            if key in data and isinstance(data.get(key), dict):
                data = data[key]
                moved = True
                break
        if not moved:
            break
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, api_errors=None,
                    input_summary=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "success", "errors": [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": CRITERIA_KEY, "vendor": "ManageEngine", "category": "EPP"},
        },
    }


def not_evaluated(reason, validation=None, extra=None):
    result = {CRITERIA_KEY: None}
    if extra:
        result.update(extra)
    return create_response(result, validation=validation, api_errors=[reason], fail_reasons=[reason],
                           input_summary=result)


def blank(value):
    return value is None or str(value).strip().lower() in ("", "null", "none", "--")


def to_int(value):
    try:
        if value is None or isinstance(value, bool):
            return None
        return int(str(value).strip())
    except Exception:
        return None


def vendor_error(body):
    """The reason this body is not a device list from the vendor, or None when it is one."""
    if not isinstance(body, dict):
        return "the anti-malware device read returned no JSON object"
    if body.get("error") is True or body.get("errorType"):
        return "the anti-malware device read failed: " + str(body.get("message") or body.get("errorType") or "error")
    if body.get("errorCode") or body.get("error_code"):
        return "ManageEngine returned " + str(body.get("errorCode") or body.get("error_code")) + ": " + \
            str(body.get("errorMessage") or body.get("errorMsg") or body.get("error_description") or "")
    status = str(body.get("status") or "").lower()
    if status and status != "success":
        return "ManageEngine answered with status " + status
    if not isinstance(body.get("messageResponse"), list):
        return "the anti-malware device read carried no device list (messageResponse)"
    return None


def truncation(body, rows):
    total = to_int(body.get("totalRecords"))
    if total is not None and total > len(rows):
        return "the device list is truncated: " + str(len(rows)) + " of " + str(total) + " devices returned"
    links = body.get("Links") or body.get("links") or {}
    if isinstance(links, dict) and not blank(links.get("next")):
        return "the device list is truncated: ManageEngine reports another page"
    pages = to_int(body.get("totalPages"))
    meta = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    page = to_int(meta.get("page"))
    if pages is not None and pages > 1 and (page is None or page < pages):
        return "the device list is truncated: page " + str(page) + " of " + str(pages)
    return None


def device_status(row):
    for key in ("component_status", "component_status_transform", "status"):
        if not blank(row.get(key)):
            return STATUS_NAMES.get(str(row.get(key)).strip().lower(), "unknown"), str(row.get(key))
    return "unknown", ""


def judged_devices(rows):
    """(judged rows, stale count, rows without a contact time); judged = within 15 days of the newest check-in."""
    times = []
    for row in rows:
        times.append(to_int(row.get("agent_last_contact_time")) if isinstance(row, dict) else None)
    known = [t for t in times if t is not None and t > 0]
    if not known:
        return [], 0, len(rows)
    newest = max(known)
    judged = []
    stale = 0
    untimed = 0
    for index, row in enumerate(rows):
        seen = times[index]
        if seen is None or seen <= 0:
            untimed = untimed + 1
        elif seen < newest - WINDOW_MS:
            stale = stale + 1
        else:
            judged.append(row)
    return judged, stale, untimed


def som_error(body):
    """The reason this body is not a complete Scope of Management computer list, or None."""
    if not isinstance(body, dict):
        return "the computer list read returned no JSON object"
    if body.get("error") is True or body.get("errorType"):
        return "the computer list read failed: " + str(body.get("message") or body.get("errorType") or "error")
    if str(body.get("status") or "").lower() not in ("", "success") or body.get("error_code"):
        return "ManageEngine returned " + str(body.get("error_code") or body.get("status")) + ": " + \
            str(body.get("error_description") or "")
    inner = body.get("message_response")
    if not isinstance(inner, dict) or not isinstance(inner.get("computers"), list):
        return "the computer list read carried no computers (message_response.computers)"
    total = to_int(inner.get("total"))
    count = len(inner["computers"])
    if total is None:
        return "the computer list does not report its total, so completeness cannot be shown"
    if total > count:
        return "the computer list is truncated: " + str(count) + " of " + str(total) + " computers returned"
    return None


def transform(input):
    try:
        data, validation = extract_input(parse_input(input))
    except Exception as exc:
        return not_evaluated("input could not be read: " + str(exc))
    if not isinstance(data, dict) or "computers" not in data or "edrDevices" not in data:
        reason = "the coverage workflow did not return both reads (computers, edrDevices)"
        if isinstance(data, dict) and (data.get("error") is True or data.get("errorCode") or data.get("error_code")):
            reason = reason + "; a step failed: " + str(data.get("message") or data.get("errorMessage") or
                                                        data.get("error_description") or data.get("errorType"))
        return not_evaluated(reason, validation)
    som = data["computers"]
    edr = data["edrDevices"]
    problem = som_error(som)
    if problem:
        return not_evaluated(problem, validation)
    problem = vendor_error(edr)
    if problem:
        return not_evaluated(problem, validation)
    edr_rows = [row for row in edr["messageResponse"] if isinstance(row, dict)]
    if not edr_rows:
        return not_evaluated("no device carries ManageEngine anti-malware protection, so this tool cannot speak "
                             "for the fleet", validation, {"protectionDevicesReported": 0})
    cut = truncation(edr, edr_rows)
    if cut:
        return not_evaluated(cut, validation)
    computers = [c for c in som["message_response"]["computers"] if isinstance(c, dict)]
    installed = [c for c in computers if to_int(c.get("installation_status")) == 22]
    not_installed = len(computers) - len(installed)
    in_scope, stale, untimed = judged_devices(installed)
    counts = {"computersReported": len(computers), "agentNotInstalledCount": not_installed,
              "computersInScope": len(in_scope), "staleComputerCount": stale,
              "computersWithoutContactTime": untimed, "protectionDevicesReported": len(edr_rows)}
    if not in_scope:
        return not_evaluated("no computer with the agent installed checked in within 15 days of the newest "
                             "check-in", validation, counts)
    status_by_id = {}
    for row in edr_rows:
        rid = str(row.get("resource_id") or "").strip()
        if rid:
            status_by_id[rid] = device_status(row)
    covered = 0
    missing = 0
    stopped = 0
    unknown = []
    for computer in in_scope:
        rid = str(computer.get("resource_id") or computer.get("resource_id_string") or "").strip()
        if not rid or rid not in status_by_id:
            missing = missing + 1
            continue
        name, raw = status_by_id[rid]
        if name in ("active", "quarantined"):
            covered = covered + 1
        elif name in ("not_enabled", "inactive"):
            stopped = stopped + 1
        else:
            unknown.append(str(computer.get("resource_name") or computer.get("full_name") or rid) +
                           " (status " + (raw or "missing") + ")")
    counts["coveredComputerCount"] = covered
    counts["computersWithoutProtection"] = missing
    counts["computersProtectionNotRunning"] = stopped
    if unknown:
        counts["unreadableStatusCount"] = len(unknown)
        return not_evaluated("anti-malware status is not a documented value on " + str(len(unknown)) +
                             " computer(s): " + ", ".join(unknown[:5]), validation, counts)
    value = (100 * covered) // len(in_scope)
    result = dict(counts)
    result[CRITERIA_KEY] = value
    findings = [str(covered) + " of " + str(len(in_scope)) + " in-scope computers have ManageEngine anti-malware "
                "protection running (" + str(value) + "%)"]
    if missing:
        findings.append(str(missing) + " in-scope computer(s) do not appear in the anti-malware device list")
    if stopped:
        findings.append(str(stopped) + " in-scope computer(s) have anti-malware installed but not running")
    if stale:
        findings.append(str(stale) + " computer(s) have not checked in within 15 days of the newest check-in")
    return create_response(result, validation=validation, input_summary=counts, additional_findings=findings)
