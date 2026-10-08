import json
import re
from datetime import datetime, timedelta


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
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
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    return data, validation


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Create the standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    data_collection_status = "error" if api_err_list else "success"
    transformation_status = "error" if transform_err_list else "success"
    response_metadata = {
        "evaluatedAt": datetime.utcnow().isoformat() + "Z",
        "schemaVersion": "2.0",
    }
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": data_collection_status, "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": transformation_status,
                "errors": transform_err_list,
                "inputSummary": input_summary or {},
            },
            "evaluation": {
                "passReasons": pass_reasons or [],
                "failReasons": fail_reasons or [],
                "recommendations": recommendations or [],
                "additionalFindings": additional_findings or [],
            },
            "metadata": response_metadata,
        },
    }


def as_int(value):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def is_rfm(value):
    """CrowdStrike reports reduced_functionality_mode as "yes"/"no" (not a boolean), so the old
    `rfm is not True` test counted every RFM sensor as active."""
    return value is True or str(value).strip().lower() in ("yes", "true")


# A host counts as reporting only when its last_seen is within this many days of the response's
# clock. The same window, clock and rule are written identically in isEPPConfiguredFromHosts.py, so
# a host this check counts as not reporting is the host that check leaves out, and the reverse.
# It matches the 15-day endpoint rule the Sophos and NinjaOne checks already apply.
ACTIVE_WINDOW_DAYS = 15


def parse_time(value):
    """An ISO timestamp (seconds, any fraction, then Z, an explicit offset, or nothing) as naive UTC.
    Falcon sends Z; an offset is converted rather than dropped. None if unreadable."""
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


def reference_clock(devices):
    """The newest last_seen in the response, so a scan of cached data judges hosts against the data's
    own time. When that newest check-in is itself older than the window the whole fleet is dark, and
    the wall clock is used so every host is stale rather than every host fresh."""
    known = [parse_time(d.get("last_seen")) for d in devices if isinstance(d, dict)]
    known = [t for t in known if t is not None]
    wall = datetime.utcnow()
    if not known:
        return wall
    # Capped at the wall clock: one future-dated record must not make every real host stale.
    newest = min(max(known), wall)
    if newest < wall - timedelta(days=ACTIVE_WINDOW_DAYS):
        return wall
    return newest


def is_reporting(device, clock):
    """A missing or unreadable last_seen is not reporting, never reporting."""
    seen = parse_time(device.get("last_seen"))
    return seen is not None and seen >= clock - timedelta(days=ACTIVE_WINDOW_DAYS)


# Falcon's status field is network containment state. A contained host still runs a working sensor,
# so it is covered; it is counted separately so the output shows it. Any other status is not covered.
CONTAINMENT_STATUSES = ("contained", "containment_pending", "lift_containment_pending")


def transform(input):
    """
    requiredCoveragePercentage (CrowdStrike, GET /devices/combined/devices/v1).

    Percentage of returned devices whose sensor is active: last_seen within ACTIVE_WINDOW_DAYS of the
    newest check-in in the response (see reference_clock), status "normal" or a network containment
    state (counted separately as contained), not in reduced functionality mode, and an agent_version. Each inactive host is counted under the first of those
    tests it fails, in that order, so the output explains the gap. Not measured (dataCollection error, shown
    Unevaluated) on an API error, or when the device list is truncated: meta.pagination.total larger
    than the devices returned (an unpaged call returns the first 100), or a merged paginated
    response marked truncated. A percentage of a sample is not the estate's coverage.
    """
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        try:
            input = json.loads(input) if input.strip() else None
        except ValueError:
            input = None
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    api_errors = []
    if data.get("error") or data.get("errorType") == "internal" or str(data.get("status", "")).lower() == "error":
        msg = data.get("errorMessage") or data.get("message") or "Unknown API error"
        api_errors.append(f"CrowdStrike API returned an error: {msg}")

    resources = data.get("resources")
    if not isinstance(resources, list):
        resources = []

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    reported_total = as_int(pagination.get("total"))
    truncated_flag = pagination.get("truncated") is True or str(pagination.get("truncated")).strip().lower() == "true"
    if not api_errors and ((reported_total is not None and reported_total > len(resources)) or truncated_flag):
        api_errors.append(
            f"Device list was truncated: {len(resources)} of {reported_total if reported_total is not None else 'unknown'} "
            "devices returned; coverage not evaluated on a sample (add pagination to the device method)"
        )

    total = len(resources)
    clock = reference_clock(resources)
    active = 0
    not_reporting = 0
    not_normal = 0
    contained = 0
    rfm_hosts = 0
    no_agent = 0
    for device in resources:
        if not isinstance(device, dict):
            continue
        if not is_reporting(device, clock):
            not_reporting = not_reporting + 1
        elif device.get("status") != "normal" and device.get("status") not in CONTAINMENT_STATUSES:
            not_normal = not_normal + 1
        elif is_rfm(device.get("reduced_functionality_mode")):
            rfm_hosts = rfm_hosts + 1
        elif not device.get("agent_version"):
            no_agent = no_agent + 1
        else:
            active = active + 1
            if device.get("status") in CONTAINMENT_STATUSES:
                contained = contained + 1
    window = f"within {ACTIVE_WINDOW_DAYS} days of the newest check-in ({clock.isoformat()}Z)"

    if total > 0:
        percentage = round((active / total) * 100, 2)
    else:
        percentage = 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if api_errors:
        percentage = 0
        fail_reasons.append("Not measured: " + "; ".join(api_errors))
        recommendations.append(
            "Verify the CrowdStrike API credentials (Hosts: Read) and that the device method pages through the "
            "whole estate, then re-run the scan."
        )
    elif total > 0:
        pass_reasons.append(
            f"{active} of {total} known Falcon-managed devices have a last_seen {window}, "
            f"status 'normal' or network-contained, reduced_functionality_mode not on, and a populated "
            f"agent_version, yielding a sensor coverage of {percentage}%."
        )
        if contained:
            pass_reasons.append(
                f"{contained} of the covered devices are network-contained: the sensor is working and the "
                "host is isolated, so it counts as covered. Review and lift containment in Falcon when the "
                "incident is resolved."
            )
        if percentage < 100:
            fail_reasons.append(
                f"{total - active} of {total} devices ({round(100 - percentage, 2)}%) do not have an "
                f"actively-reporting Falcon sensor: {not_reporting} not seen {window} (or no readable "
                f"last_seen), {not_normal} with a status that is neither 'normal' nor a containment state, {rfm_hosts} in reduced "
                f"functionality mode, {no_agent} with no agent_version."
            )
            if not_reporting:
                recommendations.append(
                    f"{not_reporting} hosts have not checked in for more than {ACTIVE_WINDOW_DAYS} days: "
                    "bring them back online, or remove decommissioned hosts from Falcon host management."
                )
            if not_normal:
                recommendations.append(
                    f"{not_normal} hosts report a status that is neither 'normal' nor a containment state: "
                    "review them in Falcon host management."
                )
            if rfm_hosts or no_agent:
                recommendations.append(
                    "Reinstall or repair the Falcon sensor on hosts in reduced functionality mode or with "
                    "no agent version."
                )
    else:
        fail_reasons.append(
            "No device records were returned by getDeviceDetails; coverage percentage could not be computed "
            "(total known devices = 0)."
        )
        recommendations.append(
            "Verify the CrowdStrike Falcon API credentials and device inventory query returned results before "
            "recomputing sensor coverage."
        )

    result = {
        "requiredCoveragePercentage": percentage,
        "activeDevices": active,
        "totalDevices": total,
        "notReportingDevices": not_reporting,
        "containedDevices": contained,
        "activeWindowDays": ACTIVE_WINDOW_DAYS,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalDevices": total,
            "activeDevices": active,
            "notReportingDevices": not_reporting,
            "statusNotNormalDevices": not_normal,
            "containedDevices": contained,
            "reducedFunctionalityDevices": rfm_hosts,
            "noAgentVersionDevices": no_agent,
            "activeWindowDays": ACTIVE_WINDOW_DAYS,
            "referenceClock": clock.isoformat() + "Z",
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
        api_errors=api_errors,
    )
