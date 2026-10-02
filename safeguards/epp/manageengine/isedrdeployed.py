"""
Transformation: isEDRDeployed
Vendor: ManageEngine Endpoint Central  |  Category: EPP
Evaluates: whether the Endpoint Central agent is installed on at least 80% of the computers in Scope of
Management, from the SoM summary.
Source: GET /api/1.4/som/summary

Shape read (Endpoint Central Cloud and on-premises; the cloud sends counts as strings, on-premises as numbers):
    {"message_type": "summary", "status": "success",
     "message_response": {"summary": {
         "installation_status_summary": {"installed": .., "total": .., "yet_to_install": .., "installation_failed": ..,
                                         "uninstalled": .., "uninstallation_failed": ..},
         "live_status_summary": {"live": .., "down": .., "unknown": ..},          (cloud only)
         "last_contact_time_summary": {"greater_30_day": .., ...}}}}

The earlier version read the counts at the top level (total_computers, managed_computers), found none, and
scored False with "0 of 0 endpoints" for a tenant whose agent is installed on almost every computer. Flat count
keys are still accepted when a body carries them explicitly.

Coverage = installed / total. The value is True at 80% or above and False below it.

Not evaluated (isEDRDeployed None, dataCollection "error"): no JSON object, a vendor or auth error body
(status other than success, error_code, IS error envelope), no installation summary, a total of 0, a count
that is missing or not a whole number, or installed above total.

This counts the Endpoint Central management agent. It does not show that any protection module on that agent
is running.
"""
import json
from datetime import datetime

CRITERIA_KEY = "isEDRDeployed"
COVERAGE_THRESHOLD = 80.0
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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    api_errors=None, input_summary=None, additional_findings=None):
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
                           "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": CRITERIA_KEY, "vendor": "ManageEngine", "category": "EPP"},
        },
    }


def not_evaluated(reason, validation=None):
    result = {CRITERIA_KEY: None}
    return create_response(result, validation=validation, api_errors=[reason], fail_reasons=[reason],
                           input_summary=result)


def to_count(value):
    """A non-negative whole number from an int or a digit string; None for anything else."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, float):
        return int(value) if value >= 0 and value == int(value) else None
    text = str(value).strip()
    if not text.isdigit():
        return None
    return int(text)


def vendor_error(body):
    """The reason this body is not a SoM summary from the vendor, or None when it may be one."""
    if not isinstance(body, dict):
        return "the SoM summary read returned no JSON object"
    if not body:
        return "the SoM summary read returned an empty body"
    if body.get("error") is True or body.get("errorType"):
        return "the SoM summary read failed: " + str(body.get("message") or body.get("errorType") or "error")
    if body.get("error_code") or body.get("errorCode"):
        return "ManageEngine returned " + str(body.get("error_code") or body.get("errorCode")) + ": " + \
            str(body.get("error_description") or body.get("errorMessage") or body.get("message") or "")
    status = str(body.get("status") or "").strip().lower()
    if status and status != "success":
        return "ManageEngine answered with status " + status + ": " + \
            str(body.get("message") or body.get("error_description") or "")
    return None


def find_counts(body):
    """(installed, total, summary dict or None, how) from the nested or the flat shape; counts may be None."""
    inner = body.get("message_response")
    if isinstance(inner, dict):
        summary = inner.get("summary") if isinstance(inner.get("summary"), dict) else inner
        install = summary.get("installation_status_summary")
        if isinstance(install, dict):
            return to_count(install.get("installed")), to_count(install.get("total")), summary, "nested"
    summary = body.get("summary")
    if isinstance(summary, dict) and isinstance(summary.get("installation_status_summary"), dict):
        install = summary["installation_status_summary"]
        return to_count(install.get("installed")), to_count(install.get("total")), summary, "nested"
    if isinstance(body.get("installation_status_summary"), dict):
        install = body["installation_status_summary"]
        return to_count(install.get("installed")), to_count(install.get("total")), body, "nested"
    total_keys = ["total_computers", "totalComputers"]
    installed_keys = ["agent_installed_count", "agentInstalledCount", "managed_computers", "managedComputers"]
    total = None
    installed = None
    for key in total_keys:
        if key in body:
            total = to_count(body.get(key))
            break
    for key in installed_keys:
        if key in body:
            installed = to_count(body.get(key))
            break
    if total is not None or installed is not None or any(k in body for k in total_keys + installed_keys):
        return installed, total, None, "flat"
    return None, None, None, None


def section_count(summary, section, key):
    if not isinstance(summary, dict) or not isinstance(summary.get(section), dict):
        return None
    return to_count(summary[section].get(key))


def transform(input):
    try:
        data, validation = extract_input(parse_input(input))
    except Exception as exc:
        return not_evaluated("input could not be read: " + str(exc))
    try:
        problem = vendor_error(data)
        if problem:
            return not_evaluated(problem, validation)
        installed, total, summary, how = find_counts(data)
        if how is None:
            return not_evaluated("the SoM summary carried no installation summary "
                                 "(message_response.summary.installation_status_summary)", validation)
        if installed is None or total is None:
            return not_evaluated("the SoM summary is missing the installed or total count, or it is not a whole number",
                                 validation)
        if total == 0:
            return not_evaluated("the SoM summary reports 0 computers in Scope of Management, so there is nothing "
                                 "to measure", validation)
        if installed > total:
            return not_evaluated("the SoM summary reports more installed agents (" + str(installed) +
                                 ") than computers (" + str(total) + ")", validation)

        coverage = (installed * 100.0) / total
        value = coverage >= COVERAGE_THRESHOLD
        pct = round(coverage, 2)
        result = {CRITERIA_KEY: value, "totalEndpoints": total, "agentDeployedCount": installed,
                  "agentNotDeployedCount": total - installed, "coveragePercentage": pct}

        findings = []
        live = section_count(summary, "live_status_summary", "live")
        down = section_count(summary, "live_status_summary", "down")
        if live is not None and down is not None:
            result["liveAgentCount"] = live
            result["downAgentCount"] = down
            findings.append(str(down) + " installed agents are reported down (" + str(live) + " live)")
        stale = section_count(summary, "last_contact_time_summary", "greater_30_day")
        if stale is not None:
            result["noContactOver30DaysCount"] = stale
            if stale > 0:
                findings.append(str(stale) + " agents have not contacted the server in over 30 days")
        yet = section_count(summary, "installation_status_summary", "yet_to_install")
        if yet is not None:
            result["yetToInstall"] = yet
        for name in ("yet_to_install", "installation_failed", "uninstalled", "uninstallation_failed"):
            count = section_count(summary, "installation_status_summary", name)
            if count:
                findings.append(str(count) + " computers: " + name.replace("_", " "))

        line = ("Endpoint Central agent installed on " + str(installed) + " of " + str(total) +
                " computers (" + str(pct) + "%)")
        if value:
            return create_response(result, validation=validation, pass_reasons=[line],
                                   input_summary=result, additional_findings=findings)
        return create_response(result, validation=validation,
                               fail_reasons=[line + " - below the " + str(COVERAGE_THRESHOLD) + "% threshold"],
                               recommendations=["Deploy the Endpoint Central agent to the remaining computers "
                                                "via SoM > Install Agent"],
                               input_summary=result, additional_findings=findings)
    except Exception as exc:
        return not_evaluated("transformation error: " + str(exc), validation)
