"""
Transformation: epp_transform (Windows Defender)
Vendor: Microsoft Defender for Endpoint
Category: Endpoint Security

Answers isEPPEnabled, isEPPDeployed, isEDRDeployed and isEPPLoggingEnabled from the Defender for
Endpoint machine inventory, GET /api/machines (Machine resource type: onboardingStatus, healthStatus,
lastSeen).

This file used to be a copy of the Sophos Central transform, reading Sophos fields
(items[].assignedProducts, health.services.serviceDetails, type == "computer") out of a Defender
ALERT list. No Defender payload carries those fields, so one alert made six controls pass and a
clean tenant with no alerts failed all of them. An alert proves Defender detected something once; it
is not evidence that protection is deployed, enabled or logging. A body that is not a machine
inventory -- the alert list included -- is now not measured (None, dataCollection error), never an
answer.

Reporting: onboardingStatus "onboarded" (any casing) AND lastSeen within ACTIVE_WINDOW_DAYS of now.
  isEPPEnabled / isEPPDeployed / isEDRDeployed -- at least one eligible machine is reporting.
      Onboarding to Defender for Endpoint is the EDR sensor; this is the same reading the One-Click
      definition takes (microsoft_endpoint_edrdeployed.py), plus recency.
  isEPPLoggingEnabled -- at least one machine is reporting, and every reporting machine's
      healthStatus is Active (its sensor is sending data).
Not measured: an error body, records with no onboardingStatus (the alert list is one), a page with
@odata.nextLink still set, no eligible machine at all, or a reporting machine that carries no
healthStatus (one missing field used to read as a logging failure). dataCollection.status is one
flag for the whole response, so if any key cannot be decided none is reported -- a key left None
under a "success" status would be graded as a failure nobody measured.

A pass on the three deployment keys says the sensor is deployed somewhere, not that it covers the
fleet: one reporting machine out of a thousand passes all three, the same reading as One-Click's
microsoft_endpoint_edrdeployed.py. requiredCoveragePercentage is the control that grades coverage,
and additionalFindings carries the reporting/eligible gap beside the verdict.
"""

import json
import re
from datetime import datetime, timedelta


# Microsoft documents lastSeen as "the last received full device report. A device typically sends a
# full report every 24 hours", and counts a device silent for more than seven days as Inactive. 15 days
# is the endpoint window the CrowdStrike, SentinelOne and Sophos checks already apply, written the same
# way in requiredcoveragepercentage.py so both files agree on which machine is reporting.
ACTIVE_WINDOW_DAYS = 15
INELIGIBLE_STATUSES = ("unsupported", "insufficientinfo")
KEYS = ("isEPPEnabled", "isEPPDeployed", "isEDRDeployed", "isEPPLoggingEnabled")


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
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


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, transformation_errors=None, api_errors=None, additional_findings=None):
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {
                "status": "error" if (api_errors or []) else "success",
                "errors": api_errors or []
            },
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
                "transformationId": "epp_transform",
                "vendor": "Microsoft Defender for Endpoint",
                "category": "Endpoint Security"
            }
        }
    }


def parse_time(value):
    """An ISO timestamp (seconds, any fraction, then Z, an explicit offset, or nothing) as naive UTC.
    Microsoft sends seven fractional digits and Z. None if unreadable."""
    if not isinstance(value, str):
        return None
    match = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})?$", value.strip())
    if not match:
        return None
    try:
        when = datetime.fromisoformat(match.group(1))
    except ValueError:
        return None
    offset = match.group(3)
    if offset and offset != "Z":
        shift = timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
        when = when - shift if offset[0] == "+" else when + shift
    return when


def status_of(machine):
    return str(machine.get("onboardingStatus") or "").strip().lower()


def read_machines(data, raw):
    """(machines, partial, reason). machines is None when the body is not a readable machine list."""
    if isinstance(data, list):
        data = {"value": data}
    if not isinstance(data, dict) or "error" in data or "PSError" in data:
        return None, False, "Microsoft Defender did not return a machine list (error or unreadable body)"
    machines = data.get("value")
    if not isinstance(machines, list):
        return None, False, "Microsoft Defender response carries no value[] machine list"
    if any(not isinstance(machine, dict) for machine in machines):
        return None, False, "Microsoft Defender machine list contains a record that is not a machine"
    alert_list = (isinstance(raw, dict) and "alerts" in raw) or any("alertCreationTime" in m for m in machines)
    if alert_list:
        return None, False, ("This is the Defender alert list (GET /api/alerts). An alert does not evidence "
                             "endpoint protection; these checks read the machine inventory (getMachines)")
    if machines and not any("onboardingStatus" in machine for machine in machines):
        return None, False, "No machine record carries onboardingStatus, so onboarding cannot be read"
    if not machines:
        return None, False, "The Defender machine inventory is empty; there is nothing to measure"
    next_link = data.get("@odata.nextLink")
    partial = isinstance(next_link, str) and next_link.strip() not in ("", "None", "null")
    return machines, partial, None


def measure(machines, partial):
    """Values for KEYS, None where this read cannot decide."""
    cutoff = datetime.utcnow() - timedelta(days=ACTIVE_WINDOW_DAYS)
    eligible = [m for m in machines
                if str(m.get("isExcluded", "false")).lower() != "true" and status_of(m) not in INELIGIBLE_STATUSES]
    onboarded = [m for m in eligible if status_of(m) == "onboarded"]
    reporting = [m for m in onboarded
                 if parse_time(m.get("lastSeen")) is not None and parse_time(m.get("lastSeen")) >= cutoff]
    healthy = [m for m in reporting if str(m.get("healthStatus") or "").strip().lower() == "active"]
    counts = {
        "eligibleDevices": len(eligible),
        "onboardedDevices": len(onboarded),
        "reportingDevices": len(reporting),
        "activeSensorDevices": len(healthy),
    }
    values = {}
    for key in KEYS:
        values[key] = None
    if partial or not eligible:
        return values, counts
    # EVERY reporting machine has to carry healthStatus, not just one of them. A machine without
    # the field got "" here, fell out of healthy, and read isEPPLoggingEnabled False -- a fail
    # nobody measured, which is the failure this file exists to remove. dataCollection.status is
    # one flag for the whole response, so an unreadable sensor health leaves every key None.
    if reporting and not all("healthStatus" in m for m in reporting):
        return values, counts
    for key in ("isEPPEnabled", "isEPPDeployed", "isEDRDeployed"):
        values[key] = len(reporting) > 0
    values["isEPPLoggingEnabled"] = len(reporting) > 0 and len(healthy) == len(reporting)
    return values, counts


def transform(input):
    values = {}
    for key in KEYS:
        values[key] = None
    counts = {}
    reason = None
    validation = {"status": "unknown", "errors": [], "warnings": []}
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            reason = "Input validation failed"
        else:
            raw = input.get("data") if isinstance(input, dict) and "validation" in input else input
            machines, partial, reason = read_machines(data, raw)
            if machines is not None:
                values, counts = measure(machines, partial)
                if not counts["eligibleDevices"]:
                    reason = "No eligible machine in the Defender inventory; nothing to measure"
                elif partial:
                    reason = ("The machine list has more pages than were read (@odata.nextLink present); "
                              "not judged on a sample")
                elif values["isEPPDeployed"] is None:
                    reason = ("Not every reporting machine carries healthStatus, so sensor health cannot be "
                              "read for the whole inventory")
                line = (str(counts["reportingDevices"]) + " of " + str(counts["eligibleDevices"])
                        + " eligible machines are onboarded to Defender for Endpoint and sent a full device report "
                        "within " + str(ACTIVE_WINDOW_DAYS) + " days; " + str(counts["activeSensorDevices"])
                        + " of those report an Active sensor")
                if values["isEPPDeployed"] is not None:
                    # These three keys read "at least one machine is reporting", so a pass says
                    # nothing about how much of the fleet is covered. Put the gap beside the
                    # verdict so a reviewer sees it without opening the transformed response;
                    # requiredCoveragePercentage is the control that grades it.
                    if counts["reportingDevices"] < counts["eligibleDevices"]:
                        additional_findings.append(
                            str(counts["eligibleDevices"] - counts["reportingDevices"]) + " of "
                            + str(counts["eligibleDevices"]) + " eligible machines are not reporting to Defender "
                            "for Endpoint. These keys read whether the sensor is deployed at all, not how much "
                            "of the fleet it covers; requiredCoveragePercentage grades the coverage")
                    if values["isEPPDeployed"]:
                        pass_reasons.append(line)
                    if values["isEPPDeployed"] is False or values["isEPPLoggingEnabled"] is False:
                        fail_reasons.append(line)
                    if values["isEPPDeployed"] is False:
                        recommendations.append("Onboard the organisation's devices to Defender for Endpoint, and "
                                               "investigate onboarded devices that have stopped reporting")
                    elif values["isEPPLoggingEnabled"] is False:
                        recommendations.append("Repair the sensors on onboarded devices whose health status is "
                                               "not Active")
    except Exception as e:
        values = {}
        for key in KEYS:
            values[key] = None
        reason = "Transformation error: " + str(e)

    # Measured is decided by the values, never by the branch: one key left None makes the whole read a
    # data-collection error, because the status is shared by every key in the response.
    measured = all(values.get(key) is not None for key in KEYS)
    unmeasured_reason = reason or "Endpoint protection could not be measured from this read"
    result = dict(values)
    result.update(counts)
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons if measured else [unmeasured_reason],
        recommendations=recommendations,
        input_summary=counts,
        api_errors=[] if measured else [unmeasured_reason],
        additional_findings=additional_findings if measured else [],
    )
