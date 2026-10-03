import json
from datetime import datetime

# ---- fail-closed guard (2026-10-03) ------------------------------------------------------------
# A read that proves nothing about the estate is Unevaluated: every key None plus a dataCollection
# error with the reason, never False. That covers no body, a body that is not JSON, an error body
# (an errors list, an error flag or an HTTP status >= 400 at any wrapper level), a body with no
# Falcon host records (for example the customer-settings body of getLicenseStatus), and a partial
# read (meta.pagination.total above the records read, a paginationTruncated or
# meta.pagination.truncated flag, or a next-page token left) that would otherwise have produced
# False. A partial read that already shows the sensor on a host still answers True: hosts not
# read cannot undo a host that was read.
#
# Reduced Functionality Mode (2026-10-03): Falcon reports reduced_functionality_mode as "yes" / "no",
# not a boolean. "yes", "true" or True (trimmed, any case) is RFM and the host is not counted as
# deployed; "no", "false" or False is not RFM. A missing field (or null) does not block the host, as
# before. Any other value is unknown: when no host proves the sensor and a host with an unknown value
# would otherwise count as deployed, the verdict is Unevaluated (dataCollection error with a reason).

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


#: reduced_functionality_mode values (trimmed, any case) that mean the sensor is / is not in RFM
RFM_YES = ("yes", "true")
RFM_NO = ("no", "false")


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


METADATA = {"transformationId": "isEDRDeployed", "vendor": "CrowdStrike Falcon", "category": "epp"}


def unevaluated(problem, validation=None, transformation_errors=None, input_summary=None):
    """isEDRDeployed as None plus a dataCollection error: reads Unevaluated, never True or False."""
    return create_response(
        result={"isEDRDeployed": None, "totalDevices": None, "deployedCount": None},
        validation=validation,
        fail_reasons=[problem],
        recommendations=["Verify CrowdStrike API credentials (clientId/clientSecret) and OAuth scopes for the Hosts collection, then re-run the scan."],
        input_summary=input_summary or {"totalDevices": None, "deployedCount": None, "rfmCount": None},
        api_errors=[problem],
        transformation_errors=transformation_errors,
        metadata=METADATA,
    )


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
    host_records = 0
    for item in resources:
        if is_host_record(item):
            host_records = host_records + 1
    if host_records == 0:
        return unevaluated("The response carries no Falcon host records (for example the customer-settings "
                           "body of getLicenseStatus): nothing was measured", validation)

    total_devices = len(resources)
    deployed_count = 0
    rfm_count = 0
    stale_count = 0
    sample_hosts = []
    unknown_rfm_count = 0
    unknown_rfm_deciding = 0
    unknown_rfm_values = []

    for device in resources:
        if not isinstance(device, dict):
            continue
        rfm = device.get("reduced_functionality_mode")
        state = rfm_state(rfm)
        rfm_is_true = state == "rfm"
        device_policies = device.get("device_policies") or {}
        has_sensor_update_policy = isinstance(device_policies, dict) and bool(device_policies.get("sensor_update"))
        agent_version = device.get("agent_version")
        last_seen = device.get("last_seen")

        if rfm_is_true:
            rfm_count = rfm_count + 1
        sensor_evidence = bool(agent_version) and has_sensor_update_policy
        if state == "unknown":
            unknown_rfm_count = unknown_rfm_count + 1
            if sensor_evidence:
                # this host counts as deployed unless it is in RFM, and its RFM value says neither
                unknown_rfm_deciding = unknown_rfm_deciding + 1
            if len(unknown_rfm_values) < 3:
                unknown_rfm_values.append('"' + str(rfm)[:40] + '"')

        is_deployed_and_streaming = state in ("not_rfm", "absent") and sensor_evidence
        if is_deployed_and_streaming:
            deployed_count = deployed_count + 1
            if len(sample_hosts) < 5:
                sample_hosts.append(device.get("hostname") or device.get("device_id") or "unknown")
        elif not last_seen:
            stale_count = stale_count + 1

    is_edr_deployed = total_devices > 0 and deployed_count > 0

    input_summary = {
        "totalDevices": total_devices,
        "deployedCount": deployed_count,
        "rfmCount": rfm_count,
    }
    unknown_note = ""
    if unknown_rfm_count > 0:
        input_summary["rfmUnknownCount"] = unknown_rfm_count
        unknown_note = (str(unknown_rfm_count) + " host(s) report a reduced_functionality_mode value that is "
                        "neither yes/true nor no/false (" + ", ".join(unknown_rfm_values) + ")")

    partial = partial_read(data, total_devices, truncated)
    additional_findings = []
    if partial and not is_edr_deployed:
        # False needs every host: the hosts not read may carry a streaming sensor.
        return unevaluated("None of the " + str(total_devices) + " host records read shows a streaming Falcon "
                           "sensor, but the read is partial (" + partial + "), so the hosts not read were "
                           "never measured", validation, input_summary=input_summary)
    if unknown_rfm_deciding > 0 and not is_edr_deployed:
        # False needs every host measured: a host whose RFM state is unknown may be streaming.
        return unevaluated("No host proves a streaming Falcon sensor, and " + unknown_note + "; " +
                           str(unknown_rfm_deciding) + " of them would count as deployed if not in Reduced "
                           "Functionality Mode, so the verdict cannot be decided", validation,
                           input_summary=input_summary)
    if unknown_rfm_count > 0:
        additional_findings.append(unknown_note + "; they were not counted as deployed.")
    if partial:
        additional_findings.append("Partial read (" + partial + "); the verdict rests on the deployed hosts that were read.")

    if is_edr_deployed:
        pass_reasons = [
            f"{deployed_count} of {total_devices} devices are not in Reduced Functionality Mode (reduced_functionality_mode \"no\"/false, or not reported), report a populated agent_version, and have an assigned sensor_update policy (e.g. {', '.join([str(h) for h in sample_hosts])}), confirming the Falcon sensor is installed and actively streaming EDR telemetry."
        ]
        fail_reasons = []
        recommendations = []
        if rfm_count > 0:
            recommendations.append(f"{rfm_count} device(s) are in Reduced Functionality Mode; investigate connectivity/licensing issues for those hosts to restore full EDR telemetry.")
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_devices} devices returned by getDeviceDetails are out of Reduced Functionality Mode (reduced_functionality_mode \"no\"/false, or not reported) with an assigned sensor_update policy and a populated agent_version, so EDR telemetry cannot be confirmed as active."
        ]
        recommendations = ["Investigate why Falcon sensors are reporting Reduced Functionality Mode or missing sensor_update policy assignment; reinstall or re-license affected sensors to restore full EDR streaming."]

    return create_response(
        result={
            "isEDRDeployed": is_edr_deployed,
            "totalDevices": total_devices,
            "deployedCount": deployed_count,
            "reducedFunctionalityModeCount": rfm_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=METADATA,
        additional_findings=additional_findings,
    )
