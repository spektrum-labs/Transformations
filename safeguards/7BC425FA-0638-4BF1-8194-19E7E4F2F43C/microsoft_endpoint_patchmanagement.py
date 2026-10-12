"""
Transformation: isPatchManagementEnabled / isPatchManagementValid
Vendor: Microsoft Defender for Endpoint (Windows Defender One-Click)  |  Category: Endpoint Security

Data source: Advanced Hunting API (POST https://api.securitycenter.microsoft.com/api/advancedqueries/run),
permission AdvancedQuery.Read.All (already granted to the One-Click app; the same route serves
isRealTimeProtectionEnabled / isTamperProtectionEnabled). The IS method getPatchComplianceStatus sends:

    let overdue = union isfuzzy=true
          (datatable(DeviceId:string, CveId:string, VulnerabilitySeverityLevel:string, RecommendedSecurityUpdate:string)[]),
          DeviceTvmSoftwareVulnerabilities
        | where isnotempty(RecommendedSecurityUpdate) and VulnerabilitySeverityLevel in ("Critical", "High")
        | join kind=inner (union isfuzzy=true (datatable(CveId:string, PublishedDate:datetime)[]),
                           DeviceTvmSoftwareVulnerabilitiesKB | project CveId, PublishedDate) on CveId
        | where PublishedDate < ago(30d)
        | summarize OverdueCritical = dcountif(CveId, VulnerabilitySeverityLevel == "Critical"),
                    OverdueHigh = dcountif(CveId, VulnerabilitySeverityLevel == "High") by DeviceId;
    union isfuzzy=true (datatable(DeviceId:string)[]), DeviceTvmSoftwareInventory
    | distinct DeviceId
    | join kind=leftouter overdue on DeviceId
    | extend OverdueCritical = coalesce(OverdueCritical, 0), OverdueHigh = coalesce(OverdueHigh, 0)
    | summarize AssessedDevices = count(),
                DevicesWithOverdueCritical = countif(OverdueCritical > 0),
                DevicesWithOverdueCriticalOrHigh = countif(OverdueCritical + OverdueHigh > 0)

One row: devices Defender Vulnerability Management inventories, and how many of them still carry a Critical
(or Critical/High) vulnerability whose vendor security update has been available for more than 30 days.

  isPatchManagementEnabled  every assessed device has no Critical vulnerability with a security update
                            published more than 30 days ago (patches are being applied).
  isPatchManagementValid    the same for Critical AND High (patching keeps up with the fleet).
Percentages are emitted (patchedCriticalPercentage, patchedCriticalHighPercentage); the verdicts are 100%.

Fails closed: an error body, no Results row, or AssessedDevices == 0 (no TVM inventory: a tenant without the
hunting tables answers an empty union, which is not a measurement) returns False with a dataCollection error.
Replaces the getAlerts read, where any alert passed both criteria.
"""
import json
from datetime import datetime


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output", "rawResponse"]
        for attempt in range(3):
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
                    input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
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
                           "recommendations": recommendations or [], "additionalFindings": additional_findings or []},
            "metadata": {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "1.0",
                         "transformationId": "microsoft_endpoint_patchmanagement",
                         "vendor": "Microsoft Defender for Endpoint", "category": "Endpoint Security"},
        },
    }


def as_count(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def not_measured(reason):
    return create_response(
        result={"isPatchManagementEnabled": False, "isPatchManagementValid": False},
        api_errors=[reason],
        fail_reasons=[reason],
        recommendations=["Confirm Defender Vulnerability Management is onboarded (DeviceTvmSoftwareInventory has rows)"],
    )


def transform(input):
    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))
        data, validation = extract_input(input)
        if isinstance(data, dict) and (data.get("error") or data.get("errors")):
            return not_measured("Defender advanced hunting returned an error")
        rows = data.get("Results") if isinstance(data, dict) else data
        if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
            return not_measured("No advanced hunting result row was returned")
        row = rows[0]
        assessed = as_count(row.get("AssessedDevices"))
        crit = as_count(row.get("DevicesWithOverdueCritical"))
        crit_high = as_count(row.get("DevicesWithOverdueCriticalOrHigh"))
        if assessed is None or crit is None or crit_high is None:
            return not_measured("The patch compliance row is missing its counts")
        if assessed <= 0:
            return not_measured("Defender Vulnerability Management inventories no devices; patch state is not measured")
        crit = min(max(crit, 0), assessed)
        crit_high = min(max(crit_high, crit), assessed)
        pct_crit = ((assessed - crit) * 100) // assessed
        pct_crit_high = ((assessed - crit_high) * 100) // assessed
        enabled = crit == 0
        valid = crit_high == 0
        pass_reasons = []
        fail_reasons = []
        recommendations = []
        line_c = (str(assessed - crit) + " of " + str(assessed) + " devices (" + str(pct_crit) + "%) have no Critical "
                  "vulnerability whose security update is more than 30 days old")
        line_h = (str(assessed - crit_high) + " of " + str(assessed) + " devices (" + str(pct_crit_high) + "%) have no "
                  "Critical or High vulnerability whose security update is more than 30 days old")
        if enabled:
            pass_reasons.append(line_c)
        else:
            fail_reasons.append(line_c)
            recommendations.append("Deploy the outstanding Critical security updates listed in Defender Vulnerability Management")
        if valid:
            pass_reasons.append(line_h)
        else:
            fail_reasons.append(line_h)
            recommendations.append("Deploy the outstanding Critical and High security updates (30-day window)")
        result = {
            "isPatchManagementEnabled": enabled,
            "isPatchManagementValid": valid,
            "patchedCriticalPercentage": pct_crit,
            "patchedCriticalHighPercentage": pct_crit_high,
            "assessedDevices": assessed,
            "devicesWithOverdueCritical": crit,
            "devicesWithOverdueCriticalOrHigh": crit_high,
        }
        return create_response(result=result, validation=validation, pass_reasons=pass_reasons,
                               fail_reasons=fail_reasons, recommendations=recommendations, input_summary=result)
    except Exception as e:
        return create_response(
            result={"isPatchManagementEnabled": False, "isPatchManagementValid": False},
            validation={"status": "error", "errors": [], "warnings": []},
            transformation_errors=[str(e)],
            fail_reasons=["Transformation error: " + str(e)],
        )
