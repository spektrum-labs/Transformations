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
    return value is True or str(value).strip().lower() in ("yes", "true")


# A host counts as reporting only when its last_seen is within this many days of the response's
# clock. The same window, clock and rule are written identically in requiredCoveragePercentage.py, so
# a host that check counts as not reporting is the host this check leaves out, and the reverse.
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


# A host whose prevention policy was assigned within PENDING_WINDOW_HOURS, which was reporting in the
# PENDING_WINDOW_HOURS before the assignment, and which has not checked in since (beyond
# PICKUP_GRACE_MINUTES after the assignment), has not yet had the chance to apply it. Such a host is
# pending: counted separately and left out of this percentage, never counted as configured. The
# window is fixed, so pending cannot last. A reassignment cannot restart the clock on a host that was
# already failing: a reporting host checks in soon after any reassignment, and once it has checked in
# past the grace with the policy still not applied it is failing again; a host that was already
# silent before the assignment is never pending, so repeated reassignment cannot keep it out.
PENDING_WINDOW_HOURS = 24
PICKUP_GRACE_MINUTES = 60


def is_pending(prevention, device, clock):
    assigned = parse_time(prevention.get("assigned_date"))
    if assigned is None or clock - assigned > timedelta(hours=PENDING_WINDOW_HOURS):
        return False
    seen = parse_time(device.get("last_seen"))
    if seen is None or assigned - seen > timedelta(hours=PENDING_WINDOW_HOURS):
        return False
    return seen <= assigned + timedelta(minutes=PICKUP_GRACE_MINUTES)


def transform(input):
    """
    isEPPConfigured (CrowdStrike, from GET /devices/combined/devices/v1, Hosts: Read).

    A whole-number percentage, floor(100 * configured / protected); the pass bar lives in the
    requirement. protected = Falcon host records returned (computers and servers; mobile hosts are
    left out), less hosts not reporting and hosts pending. configured = hosts whose prevention policy
    is applied (device_policies.prevention has a policy_id and applied true) and whose sensor is not in
    reduced functionality mode.

    A host that has not checked in within ACTIVE_WINDOW_DAYS cannot show whether its configuration is
    right, so it is left out here and counted by requiredCoveragePercentage instead. A failing host is
    reported in one of three buckets, because each needs a different fix: no prevention policy
    assigned, a policy assigned but not applied by a reporting sensor, or reduced functionality mode.
    Pending hosts (see is_pending) are reported separately.

    Not evaluated (dataCollection error, no value) on an API error, no resources list, a record that
    is not a host, a truncated device list, or no host to measure.
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
        if not api_errors:
            api_errors.append("Response has no resources list; not a Falcon host list")
        resources = []

    meta = data.get("meta") if isinstance(data.get("meta"), dict) else {}
    pagination = meta.get("pagination") if isinstance(meta.get("pagination"), dict) else {}
    reported_total = as_int(pagination.get("total"))
    truncated_flag = pagination.get("truncated") is True or str(pagination.get("truncated")).strip().lower() == "true"
    if not api_errors and ((reported_total is not None and reported_total > len(resources)) or truncated_flag):
        api_errors.append(
            f"Device list was truncated: {len(resources)} of {reported_total if reported_total is not None else 'unknown'} "
            "devices returned; not evaluated on a sample"
        )
    if not api_errors and any(not isinstance(d, dict) or not d.get("device_id") for d in resources):
        api_errors.append("Response is not a Falcon host list (a record has no device_id); check the method wiring")

    protected = 0
    configured = 0
    no_policy = 0
    not_applied = 0
    pending = 0
    not_reporting = 0
    rfm = 0
    skipped_mobile = 0
    clock = reference_clock(resources)
    if not api_errors:
        for device in resources:
            platform = str(device.get("platform_name") or "")
            if device.get("product_type_desc") == "Mobile" or platform in ("Android", "iOS"):
                skipped_mobile = skipped_mobile + 1
                continue
            if not is_reporting(device, clock):
                not_reporting = not_reporting + 1
                continue
            policies = device.get("device_policies") if isinstance(device.get("device_policies"), dict) else {}
            prevention = policies.get("prevention") if isinstance(policies.get("prevention"), dict) else {}
            applied = bool(prevention.get("policy_id")) and str(prevention.get("applied")).strip().lower() == "true"
            if is_rfm(device.get("reduced_functionality_mode")):
                rfm = rfm + 1
            elif not prevention.get("policy_id"):
                no_policy = no_policy + 1
            elif applied:
                configured = configured + 1
            elif is_pending(prevention, device, clock):
                pending = pending + 1
                continue
            else:
                not_applied = not_applied + 1
            protected = protected + 1
        if protected == 0:
            api_errors.append(
                f"No reporting Falcon computer or server to measure ({len(resources)} host records: "
                f"{skipped_mobile} mobile, {not_reporting} not seen within {ACTIVE_WINDOW_DAYS} days, "
                f"{pending} pending a prevention policy assigned within {PENDING_WINDOW_HOURS} hours)"
            )

    value = None if api_errors else (configured * 100) // protected

    pass_reasons = []
    fail_reasons = []
    recommendations = []
    additional_findings = []
    if api_errors:
        fail_reasons.append("Not measured: " + "; ".join(api_errors))
        recommendations.append(
            "Verify the CrowdStrike API credentials (Hosts: Read) and that the device method pages through the "
            "whole estate, then re-run the scan."
        )
    else:
        line = (
            f"{configured} of {protected} reporting Falcon hosts ({value}%) have their prevention policy "
            f"applied with a fully functional sensor; {no_policy} with no prevention policy assigned, "
            f"{not_applied} with a prevention policy assigned but not applied, {rfm} in reduced "
            f"functionality mode."
        )
        if configured == protected:
            pass_reasons.append(line)
        else:
            fail_reasons.append(line)
        if not_reporting:
            additional_findings.append(
                f"{not_reporting} hosts not seen within {ACTIVE_WINDOW_DAYS} days of the newest check-in "
                f"({clock.isoformat()}Z) are left out: their configuration cannot be read. They are counted "
                "as not reporting by requiredCoveragePercentage."
            )
        if pending:
            additional_findings.append(
                f"{pending} hosts are pending: a prevention policy was assigned within the last "
                f"{PENDING_WINDOW_HOURS} hours and the host has not checked in since. They are left out of "
                "this percentage, not counted as configured, until they check in or the window ends."
            )
        if no_policy:
            recommendations.append(
                f"{no_policy} hosts have no prevention policy assigned: add their host groups to an "
                "enabled prevention policy."
            )
        if not_applied:
            recommendations.append(
                f"{not_applied} hosts have a prevention policy assigned that their sensor has not applied: "
                "the assignment is already in place, so check the sensor on those hosts (sensor version "
                "supported by the policy, sensor running, connectivity to the Falcon cloud) rather than "
                "the group assignment."
            )
        if rfm:
            recommendations.append(
                f"{rfm} hosts are in reduced functionality mode: update or reinstall the Falcon sensor "
                "for the host's kernel or OS version."
            )

    summary = {
        "hostRecords": len(resources),
        "protectedHosts": protected,
        "configuredHosts": configured,
        "noAppliedPreventionPolicy": no_policy + not_applied,
        "noPreventionPolicyAssigned": no_policy,
        "preventionPolicyAssignedNotApplied": not_applied,
        "pendingPreventionPolicy": pending,
        "notReportingHosts": not_reporting,
        "activeWindowDays": ACTIVE_WINDOW_DAYS,
        "pendingWindowHours": PENDING_WINDOW_HOURS,
        "referenceClock": clock.isoformat() + "Z",
        "reducedFunctionalityMode": rfm,
        "mobileSkipped": skipped_mobile,
    }
    result = {"isEPPConfigured": value, "protectedHosts": protected, "configuredHosts": configured}

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=summary,
        metadata={
            "transformationId": "isEPPConfigured",
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
            "source": "devices/combined/devices/v1 device_policies.prevention",
        },
        api_errors=api_errors,
        additional_findings=additional_findings,
    )
