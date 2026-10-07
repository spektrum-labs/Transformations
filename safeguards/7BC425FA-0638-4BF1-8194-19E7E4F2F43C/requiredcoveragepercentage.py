"""
Transformation: requiredCoveragePercentage
Vendor: Microsoft Defender / Endpoint Protection
Category: Endpoint Security

Evaluates percentage of endpoint protection coverage for eligible machines, from
GET /api/machines (Microsoft Defender for Endpoint, Machine resource type).

Eligible: not excluded, and onboardingStatus not Unsupported or InsufficientInfo.
Protected: onboardingStatus "onboarded" (any casing) AND lastSeen within ACTIVE_WINDOW_DAYS of now.
Not measured (None, dataCollection error): an error body, a list with pages left unread
(@odata.nextLink), records that carry no onboardingStatus, or no eligible machine at all.
"""

import json
import re
from datetime import datetime, timedelta


# Microsoft documents lastSeen as "the last received full device report. A device typically sends a
# full report every 24 hours", and counts a device that sends no signal for more than seven days as
# Inactive. An onboarded machine with no full report in 15 days is not evidenced as protected; it stays
# in the denominator, so a dark machine lowers coverage rather than leaving it. 15 days matches the
# endpoint window the CrowdStrike, SentinelOne and Sophos checks already apply. The clock is the wall
# clock, so a fleet that has been dark for months scores what it is, not what it was.
ACTIVE_WINDOW_DAYS = 15
INELIGIBLE_STATUSES = ("unsupported", "insufficientinfo")


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
                "transformationId": "requiredCoveragePercentage",
                "vendor": "Microsoft Defender",
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


def read_machines(data):
    """The machine list, or the reason it cannot be measured from."""
    if isinstance(data, list):
        data = {"value": data}
    if not isinstance(data, dict) or "error" in data or "PSError" in data:
        return None, "Microsoft Defender did not return a machine list (error or unreadable body)"
    machines = data.get("value")
    if not isinstance(machines, list):
        return None, "Microsoft Defender response carries no value[] machine list"
    if any(not isinstance(machine, dict) for machine in machines):
        return None, "Microsoft Defender machine list contains a record that is not a machine"
    next_link = data.get("@odata.nextLink")
    if isinstance(next_link, str) and next_link.strip() not in ("", "None", "null"):
        return None, ("The machine list has more pages than were read (@odata.nextLink present); "
                      "coverage is not computed over a sample")
    if machines and not any("onboardingStatus" in machine for machine in machines):
        return None, "No machine record carries onboardingStatus, so onboarding cannot be read"
    return machines, None


def transform(input):
    criteriaKey = "requiredCoveragePercentage"
    value = None
    reason = None
    extra = {}
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    validation = {"status": "unknown", "errors": [], "warnings": []}

    try:
        if isinstance(input, str):
            input = json.loads(input)
        elif isinstance(input, bytes):
            input = json.loads(input.decode("utf-8"))

        data, validation = extract_input(input)

        if validation.get("status") == "failed":
            reason = "Input validation failed"
        else:
            machines, reason = read_machines(data)
            if machines is not None:
                now = datetime.utcnow()
                cutoff = now - timedelta(days=ACTIVE_WINDOW_DAYS)
                non_excluded = [m for m in machines if str(m.get("isExcluded", "false")).lower() != "true"]
                eligible = [m for m in non_excluded if status_of(m) not in INELIGIBLE_STATUSES]
                onboarded = [m for m in eligible if status_of(m) == "onboarded"]
                reporting = [m for m in onboarded
                             if parse_time(m.get("lastSeen")) is not None and parse_time(m.get("lastSeen")) >= cutoff]
                extra = {
                    "allDevices": len(machines),
                    "eligibleDevices": len(eligible),
                    "onboardedDevices": len(onboarded),
                    "protectedDevices": len(reporting),
                    "staleOnboardedDevices": len(onboarded) - len(reporting),
                }
                if not eligible:
                    reason = ("No eligible machine in the Defender inventory (" + str(len(machines))
                              + " returned, none onboardable); coverage has no denominator")
                else:
                    value = round(100 * len(reporting) / len(eligible))
                    line = (str(len(reporting)) + " of " + str(len(eligible)) + " eligible machines are onboarded "
                            "and sent a full device report within " + str(ACTIVE_WINDOW_DAYS) + " days ("
                            + str(value) + "%)")
                    if extra["staleOnboardedDevices"]:
                        line = line + "; " + str(extra["staleOnboardedDevices"]) + " onboarded machines have not reported"
                    if value >= 100:
                        pass_reasons.append(line)
                    else:
                        fail_reasons.append(line)
                        recommendations.append("Onboard the remaining eligible devices to Defender for Endpoint and "
                                               "investigate onboarded devices that have stopped reporting")
    except Exception as e:
        value = None
        reason = "Transformation error: " + str(e)

    # Measured is decided by the value, never by the branch: anything that left it None is not measured.
    measured = value is not None
    result = {criteriaKey: value}
    result.update(extra)
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons if measured else [reason or "Coverage could not be measured"],
        recommendations=recommendations,
        input_summary=extra,
        api_errors=[] if measured else [reason or "Coverage could not be measured"],
    )
