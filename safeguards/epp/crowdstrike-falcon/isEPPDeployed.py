import json
import re
from datetime import datetime, timedelta

# ---- fail-closed guard (2026-10-03) ------------------------------------------------------------
# A read that proves nothing about the estate is Unevaluated: every key None plus a dataCollection
# error with the reason, never False. That covers no body, a body that is not JSON, an error body
# (an errors list, an error flag or an HTTP status >= 400 at any wrapper level), a body with no
# Falcon host records (for example the customer-settings body of getLicenseStatus), and a partial
# read (meta.pagination.total above the records read, a paginationTruncated or
# meta.pagination.truncated flag, or a next-page token left) that would otherwise have produced
# False.
#
# Measured, not asserted (2026-10-07): this file used to answer `"isEPPDeployed": True` whenever any
# host ID or host record was present, with no branch that could return False. Replayed against real
# captured Falcon bodies it answered True for a fleet whose every host had been dark for 90 days and
# for one 100-record page of a 1,511-host tenant. isEPPDeployed is now the share of hosts with a
# reporting sensor, against DEPLOYED_THRESHOLD, from host records read whole:
#   - a host counts when it has an agent_version, is not in Reduced Functionality Mode, and checked in
#     (last_seen) within ACTIVE_WINDOW_DAYS -- the same window and clock as the sibling host checks;
#   - mobile hosts stay out of the denominator, as isEPPConfiguredFromHosts does;
#   - a host-ID list (devices-scroll, queries/devices) carries no last_seen, so it proves enrolment, not
#     a reporting sensor, and is Unevaluated; so is any partial read, since a share needs every host.

#: platform wrappers peeled off the vendor body, at most three levels deep
WRAPPER_KEYS = ("api_response", "response", "result", "apiResponse", "Output")

#: pagination fields that, when set, mean more pages were left unread
NEXT_TOKEN_KEYS = ("after", "next", "nextPage", "next_page", "nextToken", "next_token", "nextPageToken")

#: fields a Falcon host record carries; one of them marks a record as a host
HOST_FIELDS = ("device_id", "deviceId", "hostname", "agent_version", "agentVersion", "sensor_version",
               "platform_name", "os_version", "osVersion", "device_policies", "devicePolicies",
               "last_seen", "first_seen", "product_type_desc", "system_product_name", "mac_address",
               "local_ip", "reduced_functionality_mode")


def parse_body(data):
    """A JSON string or bytes body parsed; anything else unchanged. Unparseable text stays text."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except Exception:
            return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return data
    return data


def as_int(value):
    """An int, or a string of digits as an int; None for anything else (bools included)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def is_set(value):
    """True for a flag or token that is present and not blank."""
    if value is None or value is False:
        return False
    if isinstance(value, (str, list, dict)):
        return len(value) > 0 and str(value).strip().lower() not in ("", "null", "none", "false")
    return bool(value)


def level_error(level):
    """Why this level of the body is an error, or None. Checked at every wrapper level."""
    if not isinstance(level, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus"):
        code = as_int(level.get(name))
        if code is not None and code >= 400:
            return "CrowdStrike returned HTTP " + str(code)
    errors = level.get("errors")
    if is_set(errors):
        first = errors[0] if isinstance(errors, list) else errors
        if isinstance(first, dict):
            first = first.get("message") or first.get("code") or "error"
        return "CrowdStrike returned an error: " + str(first)[:200]
    for name in ("error", "errorType", "errorMessage"):
        flag = level.get(name)
        if flag is True or (isinstance(flag, (str, list, dict)) and is_set(flag)):
            detail = level.get("errorMessage") or level.get("message") or flag
            if detail is True:
                detail = "error flag set"
            return "CrowdStrike returned an error: " + str(detail)[:200]
    return None


def flag_true(flag):
    return flag is True or (isinstance(flag, str) and flag.strip().lower() == "true")


def truncation_flag(level):
    """True when this level says the platform stopped paging early (Integration-Service sets
    paginationTruncated on the envelope when it hits maxPages)."""
    if not isinstance(level, dict):
        return False
    return flag_true(level.get("paginationTruncated"))


def extract_input(input_data):
    """(data, validation, problem, truncated).

    problem is the reason the body proves nothing (None when it is usable). Wrappers are peeled
    one level at a time, and a level that carries an error stops the peel with that error.
    """
    validation = {
        "status": "unknown",
        "errors": [],
        "warnings": ["Legacy input format - no schema validation performed"],
    }
    data = parse_body(input_data)
    if data is None or (isinstance(data, (str, bytes, list, dict)) and len(data) == 0):
        return data, validation, "CrowdStrike returned no body: nothing was measured", False
    if isinstance(data, (str, bytes)):
        return data, validation, "The response is not JSON: nothing was measured", False
    if not isinstance(data, dict):
        return data, validation, "The response is not a JSON object: nothing was measured", False
    truncated = truncation_flag(data)
    if "data" in data and "validation" in data:
        problem = level_error(data)
        if problem:
            return data, validation, problem, truncated
        if isinstance(data.get("validation"), dict):
            validation = data["validation"]
        data = parse_body(data["data"])
        if not isinstance(data, dict) or len(data) == 0:
            return data, validation, "CrowdStrike returned no body: nothing was measured", truncated
        truncated = truncated or truncation_flag(data)
        return data, validation, level_error(data), truncated
    for depth in range(3):
        problem = level_error(data)
        if problem:
            return data, validation, problem, truncated
        inner = None
        for key in WRAPPER_KEYS:
            if key in data and isinstance(data.get(key), dict):
                inner = data[key]
                break
        if inner is None:
            break
        data = inner
        truncated = truncated or truncation_flag(data)
    return data, validation, level_error(data), truncated


def is_host_record(item):
    """True when `item` reads as a Falcon host record."""
    if not isinstance(item, dict):
        return False
    for name in HOST_FIELDS:
        if name in item:
            return True
    return False


def is_device_id(item):
    """True for a string shaped like a Falcon device ID (aid), as GET /devices/queries/devices-scroll returns it:
    32 hex characters. Detection ids ("ldt:..."), vulnerability-instance ids ("<aid>_<hash>") and other
    non-32-hex strings do not match. Known limit: Falcon policy ids are ALSO 32 hex, so the shape alone cannot
    tell a device id from a policy id; the definition's method binding (devices-scroll for this key) is the
    control against a misrouted policy-id list."""
    if not isinstance(item, str):
        return False
    text = item.strip().lower()
    if len(text) != 32:
        return False
    for ch in text:
        if ch not in "0123456789abcdef":
            return False
    return True


def pagination_of(data):
    meta = data.get("meta") if isinstance(data, dict) else None
    pagination = meta.get("pagination") if isinstance(meta, dict) else None
    if not isinstance(meta, dict):
        meta = {}
    if not isinstance(pagination, dict):
        pagination = {}
    return meta, pagination


def partial_read(data, records_read, truncated):
    """Why this read did not cover every host, or None when nothing says it was cut short."""
    meta, pagination = pagination_of(data)
    if truncated or truncation_flag(meta) or truncation_flag(pagination):
        return "the platform flagged the read as truncated (paginationTruncated)"
    # Integration-Service keeps the first page's pagination block and, when it stops at maxPages,
    # marks it truncated with the scannedCount.
    if flag_true(pagination.get("truncated")) or flag_true(meta.get("truncated")):
        return "the platform flagged the read as truncated (meta.pagination.truncated)"
    total = as_int(pagination.get("total"))
    if total is not None and total > records_read:
        return "meta.pagination.total reports " + str(total) + " hosts but " + str(records_read) + " were read"
    for level in (pagination, meta, data):
        for name in NEXT_TOKEN_KEYS:
            if is_set(level.get(name)):
                return "a next-page token (" + name + ") was left unread"
    return None


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
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


METADATA = {"transformationId": "isEPPDeployed", "vendor": "CrowdStrike Falcon", "category": "epp"}

#: share of non-mobile hosts (percent) that must carry a reporting, fully functional Falcon sensor
#: for isEPPDeployed to hold. The same bar the CrowdStrike MDR transform applies to isMDRConfigured.
DEPLOYED_THRESHOLD = 95.0

#: reduced_functionality_mode values (trimmed, any case) that mean the sensor is / is not in RFM
RFM_YES = ("yes", "true")
RFM_NO = ("no", "false")

#: the keys this file answers; all None when nothing was measured
RESULT_KEYS = ("isEPPDeployed", "sensorDeploymentPercentage", "totalDevices", "reportingDevices")


def unevaluated(problem, validation=None, transformation_errors=None, input_summary=None):
    """isEPPDeployed as None plus a dataCollection error: reads Unevaluated, never True or False."""
    result = {}
    for key in RESULT_KEYS:
        result[key] = None
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[problem],
        recommendations=[
            "Verify CrowdStrike API credentials/scopes, and read isEPPDeployed from host records "
            "(GET /devices/combined/devices/v1, getDeviceDetails) read in full."
        ],
        input_summary=input_summary or {"totalDevices": None, "resourcesInPage": None},
        metadata=METADATA,
        api_errors=[problem],
        transformation_errors=transformation_errors,
    )


# A host counts as reporting only when its last_seen is within this many days of the response's
# clock. The same window, clock and rule are written identically in requiredCoveragePercentage.py,
# isEPPConfiguredFromHosts.py, isEDRDeployed.py, isEPPDeployed.py and
# isPatchManagementEnabledFromHosts.py, so every CrowdStrike host check agrees on which hosts are
# reporting.
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


def rfm_state(value):
    """'rfm', 'not_rfm', 'absent' or 'unknown' for a host's reduced_functionality_mode value."""
    if value is None:
        return "absent"
    if value is True:
        return "rfm"
    if value is False:
        return "not_rfm"
    if isinstance(value, str):
        text = value.strip().lower()
        if text in RFM_YES:
            return "rfm"
        if text in RFM_NO:
            return "not_rfm"
    return "unknown"


def is_mobile(device):
    return device.get("product_type_desc") == "Mobile" or device.get("platform_name") in ("Android", "iOS")


def transform(input):
    try:
        return evaluate(input)
    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return unevaluated(message, {"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[message])


def evaluate(input):
    data, validation, problem, truncated = extract_input(input)
    if problem:
        return unevaluated(problem, validation)

    resources = data.get("resources")
    if not isinstance(resources, list) or len(resources) == 0:
        return unevaluated("CrowdStrike returned no host records. A failed or partial read returns an empty "
                           "list, so zero hosts is not evidence either way", validation)
    host_records = []
    device_ids = 0
    other_strings = 0
    for item in resources:
        if is_host_record(item):
            host_records.append(item)
        elif is_device_id(item):
            device_ids = device_ids + 1
        elif isinstance(item, str):
            other_strings = other_strings + 1
    if not host_records and device_ids == 0 and other_strings > 0:
        return unevaluated("The response lists " + str(other_strings) + " ID(s) that are not Falcon device IDs "
                           "(32 hex characters) and no host records: this is not a host list (wrong method), so "
                           "nothing was measured", validation)
    if not host_records and device_ids > 0:
        # GET /devices/queries/devices-scroll/v1 and /devices/queries/devices/v1 return host IDs only.
        return unevaluated("The response lists " + str(device_ids) + " Falcon device ID(s) and no host records. "
                           "An ID list proves a host is enrolled, not that its sensor is reporting (no "
                           "last_seen, agent_version or reduced_functionality_mode), so deployment was not "
                           "measured", validation,
                           input_summary={"totalDevices": None, "resourcesInPage": len(resources)})
    if not host_records:
        return unevaluated("The response carries no Falcon host records (for example the customer-settings "
                           "body of getLicenseStatus): nothing was measured", validation)

    total = as_int(pagination_of(data)[1].get("total"))
    input_summary = {"totalDevices": total if total is not None else len(resources),
                     "resourcesInPage": len(resources)}
    if total is not None and total <= 0:
        return unevaluated("meta.pagination.total is " + str(total) + " but " + str(len(host_records)) + " host "
                           "records were returned: the read is inconsistent, so nothing was measured",
                           validation, input_summary=input_summary)
    partial = partial_read(data, len(resources), truncated)
    if partial:
        return unevaluated("The read is partial (" + partial + "): a deployment share needs every host, so "
                           "nothing was measured", validation, input_summary=input_summary)

    clock = reference_clock(host_records)
    hosts = 0
    mobile = 0
    reporting = 0
    not_reporting = 0
    no_agent = 0
    rfm = 0
    unknown_rfm = 0
    for device in host_records:
        if is_mobile(device):
            mobile = mobile + 1
            continue
        hosts = hosts + 1
        if not is_reporting(device, clock):
            not_reporting = not_reporting + 1
            continue
        agent_version = device.get("agent_version") or device.get("agentVersion") or device.get("sensor_version")
        if not (isinstance(agent_version, str) and agent_version.strip()):
            no_agent = no_agent + 1
            continue
        state = rfm_state(device.get("reduced_functionality_mode"))
        if state == "rfm":
            rfm = rfm + 1
        elif state == "unknown":
            unknown_rfm = unknown_rfm + 1
        else:
            reporting = reporting + 1

    input_summary.update({"hostsMeasured": hosts, "mobileSkipped": mobile, "reportingDevices": reporting,
                          "notReportingDevices": not_reporting, "noAgentVersion": no_agent,
                          "reducedFunctionalityMode": rfm, "rfmUnknown": unknown_rfm,
                          "activeWindowDays": ACTIVE_WINDOW_DAYS, "thresholdPercent": DEPLOYED_THRESHOLD})
    if hosts == 0:
        return unevaluated("Every host record read is a mobile host, which this check does not measure: "
                           "nothing was measured", validation, input_summary=input_summary)

    percentage = round(reporting * 100.0 / hosts, 2)
    deployed = percentage >= DEPLOYED_THRESHOLD
    if not deployed and unknown_rfm > 0 and (reporting + unknown_rfm) * 100.0 / hosts >= DEPLOYED_THRESHOLD:
        # False needs every host decided: these hosts would carry the share over the bar unless in RFM.
        return unevaluated(str(unknown_rfm) + " reporting host(s) carry a reduced_functionality_mode value that "
                           "is neither yes/true nor no/false, and they decide whether " + str(DEPLOYED_THRESHOLD) +
                           "% is reached, so the verdict cannot be decided", validation,
                           input_summary=input_summary)

    detail = (str(reporting) + " of " + str(hosts) + " hosts (" + str(percentage) + "%) have a Falcon sensor "
              "(agent_version) that is not in Reduced Functionality Mode and checked in within " +
              str(ACTIVE_WINDOW_DAYS) + " days of the newest check-in (" + clock.isoformat() + "Z)")
    gaps = []
    if not_reporting:
        gaps.append(str(not_reporting) + " not seen within " + str(ACTIVE_WINDOW_DAYS) + " days")
    if rfm:
        gaps.append(str(rfm) + " in Reduced Functionality Mode")
    if no_agent:
        gaps.append(str(no_agent) + " with no agent_version")
    if unknown_rfm:
        gaps.append(str(unknown_rfm) + " with an unreadable reduced_functionality_mode")
    additional_findings = []
    if gaps:
        additional_findings.append("Not counted as deployed: " + ", ".join(gaps) + ".")
    if mobile:
        additional_findings.append(str(mobile) + " mobile host(s) were left out of the share.")

    if deployed:
        pass_reasons = [detail + ", at or above the " + str(DEPLOYED_THRESHOLD) + "% bar."]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [detail + ", below the " + str(DEPLOYED_THRESHOLD) + "% bar."]
        recommendations = ["Bring hosts that have stopped checking in or are in Reduced Functionality Mode back "
                           "to a reporting sensor, and hide decommissioned hosts in Falcon so they leave the "
                           "host list."]

    return create_response(
        result={"isEPPDeployed": deployed, "sensorDeploymentPercentage": percentage, "totalDevices": hosts,
                "reportingDevices": reporting},
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=METADATA,
        additional_findings=additional_findings,
    )
