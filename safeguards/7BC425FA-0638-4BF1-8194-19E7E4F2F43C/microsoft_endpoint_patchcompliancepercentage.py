"""
Transformation: patchCompliancePercentage
Vendor: Microsoft Defender for Endpoint (Windows Defender One-Click)  |  Category: Endpoint Security

Criterion (VMP-003 "Endpoint & Server Patching Policy", operator >= / > 95): the percentage of devices that
are inside the critical/high patch SLA.

Data source: the Windows Defender One-Click method getPatchComplianceStatus (Integration-Service
integration_configs/epp/windows-defender-oneclick.json), an Advanced Hunting query --
POST https://api.securitycenter.microsoft.com/api/advancedqueries/run
(https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api, AdvancedQuery.Read.All) over the
Defender Vulnerability Management tables DeviceTvmSoftwareInventory, DeviceTvmSoftwareVulnerabilities
(RecommendedSecurityUpdate) and DeviceTvmSoftwareVulnerabilitiesKB (PublishedDate):
https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwarevulnerabilities-table .
It returns one row: AssessedDevices, DevicesWithOverdueCritical, DevicesWithOverdueCriticalOrHigh, where
"overdue" means a Critical/High vulnerability whose vendor security update was published more than 30 days ago.
The same row feeds isPatchManagementEnabled/Valid (microsoft_endpoint_patchmanagement.py).

  patchCompliancePercentage = (AssessedDevices - DevicesWithOverdueCriticalOrHigh) / AssessedDevices * 100,
  rounded DOWN to one decimal so a fleet is never reported above its real compliance.

Fails closed: an error body, no Results row, a row without integer counts, or AssessedDevices == 0 (no TVM
inventory -- a tenant without the hunting tables answers an empty union) returns None with a dataCollection error.
"""
import json
from datetime import datetime

KEY = "patchCompliancePercentage"


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
                break
    return data, {"status": "unknown", "errors": [], "warnings": ["Legacy input format"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None, recommendations=None,
                    input_summary=None, api_errors=None, transformation_errors=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if (api_errors or []) else "success", "errors": api_errors or []},
            "validation": {"status": validation.get("status", "unknown"), "errors": validation.get("errors", []),
                           "warnings": validation.get("warnings", [])},
            "transformation": {"status": "error" if (transformation_errors or []) else "success",
                               "errors": transformation_errors or [], "inputSummary": input_summary or {}},
            "evaluation": {"passReasons": pass_reasons or [], "failReasons": fail_reasons or [],
                           "recommendations": recommendations or [], "additionalFindings": []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "microsoft_endpoint_patchcompliancepercentage",
                         "vendor": "Microsoft Defender for Endpoint", "category": "Endpoint Security"},
        },
    }


def not_measured(reason, validation=None):
    return create_response(
        result={KEY: None}, validation=validation, api_errors=[reason], fail_reasons=[reason],
        recommendations=["Confirm Defender Vulnerability Management is onboarded (DeviceTvmSoftwareInventory has rows)"])


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == int(value):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input) if input.strip() else None
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if isinstance(data, dict) and (data.get("error") or data.get("errors")):
            return not_measured("Defender advanced hunting returned an error", validation)
        rows = data.get("Results") if isinstance(data, dict) else None
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
            return not_measured("No advanced hunting result row was returned", validation)
        row = rows[0]
        assessed = as_count(row.get("AssessedDevices"))
        overdue = as_count(row.get("DevicesWithOverdueCriticalOrHigh"))
        if assessed is None or overdue is None:
            return not_measured("The patch compliance row is missing its device counts", validation)
        if assessed <= 0:
            return not_measured("Defender Vulnerability Management inventories no devices; patch state is not measured",
                                validation)
        if overdue < 0 or overdue > assessed:
            return not_measured("The patch compliance row is inconsistent (overdue devices outside 0.." +
                                str(assessed) + ")", validation)
        compliant = assessed - overdue
        pct = ((compliant * 1000) // assessed) / 10.0
        summary = {"assessedDevices": assessed, "devicesWithOverdueCriticalOrHigh": overdue,
                   "compliantDevices": compliant}
        line = (str(compliant) + " of " + str(assessed) + " assessed devices (" + str(pct) + "%) have no Critical or "
                "High vulnerability whose security update is more than 30 days old")
        result = {KEY: pct, "assessedDevices": assessed, "devicesWithOverdueCriticalOrHigh": overdue}
        if overdue == 0:
            return create_response(result=result, validation=validation, pass_reasons=[line], input_summary=summary)
        return create_response(
            result=result, validation=validation, fail_reasons=[line], input_summary=summary,
            recommendations=["Deploy the outstanding Critical and High security updates listed in Defender "
                             "Vulnerability Management (30-day window)"])
    except Exception as e:
        return create_response(result={KEY: None}, transformation_errors=[str(e)],
                               api_errors=["Transformation error: " + str(e)],
                               fail_reasons=["Transformation error: " + str(e)])
