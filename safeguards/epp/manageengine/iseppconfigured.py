"""
Transformation: isEPPConfigured
Vendor: ManageEngine Endpoint Central (Malware Protection / Next-Gen Antivirus add-on)  |  Category: EPP
Source: GET /edr/api/view/devices?pageLimit=1000 (OAuth scope DesktopCentralCloud.EDR.READ), the device list of
ManageEngine's anti-malware component (filed under the EDR module).

Value: a whole-number percentage, floor(100 * configured / protected), the same contract every Endpoint Security
vendor answers for this key (FF-04). protected = judged devices the anti-malware component is installed on (every
row of the list); configured = those whose protection is healthy by ManageEngine's own documented signals:
status 1 (active), error_code empty ("null if the agent is healthy"), not suspended, not network-isolated, and a
definition file version reported (def_file_version). ManageEngine pushes definitions itself (weekly behaviour
rules, monthly ML model, per its Malware Protection FAQ); its API exposes no update-schedule setting, so update
cadence is not judged here, only that a definition set is installed on a healthy, active agent. Only devices whose
agent_last_contact_time is within 15 days of the newest one in the response are judged (endpoint rules
2026-09-29); the rest are reported as staleDeviceCount. The pass bar lives in the requirement.

Not evaluated (isEPPConfigured None, dataCollection "error"): a vendor or authentication error, no device list, an
empty list, a truncated list, no device inside the window, or any judged device whose status is not one of the
documented codes (0, 1, 8, 11).
"""
import json
from datetime import datetime

CRITERIA_KEY = "isEPPConfigured"
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


def transform(input):
    try:
        data, validation = extract_input(parse_input(input))
    except Exception as exc:
        return not_evaluated("input could not be read: " + str(exc))
    if isinstance(data, dict) and isinstance(data.get("edrDevices"), dict):
        data = data["edrDevices"]
    problem = vendor_error(data)
    if problem:
        return not_evaluated(problem, validation)
    rows = [row for row in data["messageResponse"] if isinstance(row, dict)]
    if not rows:
        return not_evaluated("no device carries ManageEngine anti-malware protection, so there is no protected "
                             "device to measure", validation, {"devicesReported": 0})
    cut = truncation(data, rows)
    if cut:
        return not_evaluated(cut, validation, {"devicesReported": len(rows)})
    judged, stale, untimed = judged_devices(rows)
    counts = {"devicesReported": len(rows), "devicesJudged": len(judged), "staleDeviceCount": stale,
              "devicesWithoutContactTime": untimed}
    if not judged:
        return not_evaluated("no device checked in within 15 days of the newest check-in", validation, counts)
    configured = 0
    reasons = {"not active": 0, "agent error": 0, "suspended": 0, "isolated": 0, "no definitions": 0}
    unknown = []
    for row in judged:
        name, raw = device_status(row)
        if name == "unknown":
            unknown.append(str(row.get("resource_name_transform") or row.get("resource_id") or "device") +
                           " (status " + (raw or "missing") + ")")
            continue
        faults = []
        if name != "active":
            faults.append("not active")
        if not blank(row.get("error_code")) and str(row.get("error_code")).strip() != "0":
            faults.append("agent error")
        if str(row.get("is_suspended") or "").strip().lower() == "true":
            faults.append("suspended")
        if not blank(row.get("isolation_status")):
            faults.append("isolated")
        if blank(row.get("def_file_version")):
            faults.append("no definitions")
        for fault in faults:
            reasons[fault] = reasons[fault] + 1
        if not faults:
            configured = configured + 1
    if unknown:
        counts["unreadableStatusCount"] = len(unknown)
        return not_evaluated("anti-malware status is not a documented value on " + str(len(unknown)) +
                             " device(s): " + ", ".join(unknown[:5]), validation, counts)
    protected = len(judged)
    value = (100 * configured) // protected
    result = dict(counts)
    result[CRITERIA_KEY] = value
    result["protectedDeviceCount"] = protected
    result["configuredDeviceCount"] = configured
    shortfall = [k + " " + str(v) for k, v in reasons.items() if v]
    summary = (str(configured) + " of " + str(protected) + " judged devices have healthy, active anti-malware "
               "protection with definitions installed (" + str(value) + "%)")
    findings = [summary]
    if stale:
        findings.append(str(stale) + " device(s) have not checked in within 15 days of the newest check-in")
    if shortfall:
        findings.append("Not configured: " + ", ".join(shortfall))
    return create_response(result, validation=validation, pass_reasons=[], fail_reasons=[],
                           input_summary=counts, additional_findings=findings)
