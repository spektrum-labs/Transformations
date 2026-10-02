import json
from datetime import datetime, timezone

STALE_THRESHOLD_DAYS = 15
SECONDS_PER_DAY = 86400


def extract_input(input_data):
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for _ in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), (dict, list)):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped or not isinstance(data, dict):
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


def measure_stale(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    metadata = {"transformationId": "staleSensorCount", "vendor": "NinjaOne Endpoint Management", "category": "epp"}
    if validation.get("status") == "failed":
        return unevaluated("staleSensorCount", "Input validation failed: the device inventory did not match its "
                           "schema, so the stale count is unknown", validation, metadata)
    if isinstance(data, list):
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("devices") or data.get("apiResponse") or data.get("results") or []
        if not isinstance(devices, list):
            devices = []
    else:
        devices = []
    devices = [d for d in devices if isinstance(d, dict)]
    if not devices:
        return unevaluated("staleSensorCount", "getDevicesDetailed returned no device records (empty, missing or "
                           "error reply), so the stale count is unknown, not 0", validation, metadata,
                           {"totalDevices": 0})

    # Clock = the newest lastContact in the list (endpoint rules 2026-09-29), so a delayed
    # evaluation does not age the whole fleet; the wall clock only when none is readable.
    contacts = []
    for d in devices:
        if isinstance(d, dict):
            try:
                contacts.append(float(d.get("lastContact")))
            except (TypeError, ValueError):
                pass
    if not contacts:
        return unevaluated("staleSensorCount", "None of the " + str(len(devices)) + " device record(s) carries a "
                           "readable lastContact, so the stale count is unknown", validation, metadata,
                           {"totalDevices": len(devices)})
    wall_epoch = datetime.now(timezone.utc).timestamp()
    now_epoch = max(contacts) if contacts else wall_epoch
    if now_epoch < wall_epoch - STALE_THRESHOLD_DAYS * SECONDS_PER_DAY:
        now_epoch = wall_epoch   # dark fleet: the newest contact is itself stale, so judge by the wall clock
    stale_threshold_epoch = now_epoch - (STALE_THRESHOLD_DAYS * SECONDS_PER_DAY)

    total_devices = len(devices)
    stale_devices = []
    missing_last_contact = 0

    for device in devices:
        if not isinstance(device, dict):
            continue
        last_contact = device.get("lastContact")
        if last_contact is None:
            missing_last_contact = missing_last_contact + 1
            continue
        try:
            last_contact_val = float(last_contact)
        except (TypeError, ValueError):
            missing_last_contact = missing_last_contact + 1
            continue
        if last_contact_val < stale_threshold_epoch:
            stale_devices.append({
                "id": device.get("id"),
                "systemName": device.get("systemName"),
                "lastContact": last_contact_val,
            })

    stale_count = len(stale_devices)

    input_summary = {
        "totalDevices": total_devices,
        "staleThresholdDays": STALE_THRESHOLD_DAYS,
        "devicesMissingLastContact": missing_last_contact,
        "staleDeviceCount": stale_count,
    }

    sample_names = [d.get("systemName") or str(d.get("id")) for d in stale_devices[:5]]

    if stale_count > 0:
        pass_reasons = [
            f"{stale_count} of {total_devices} devices have lastContact older than {STALE_THRESHOLD_DAYS} days "
            f"(examples: {', '.join([n for n in sample_names if n])})."
        ]
    else:
        pass_reasons = [
            f"All {total_devices} devices have lastContact within the last {STALE_THRESHOLD_DAYS} days; {stale_count} stale sensors detected."
        ]

    fail_reasons = []
    recommendations = []
    if stale_count > 0:
        recommendations = [
            "Investigate and re-enroll or decommission devices that have not checked in for 14+ days: "
            + ", ".join([n for n in sample_names if n])
        ]

    return create_response(
        result={
            "staleSensorCount": stale_count,
            "totalDevices": total_devices,
            "devicesMissingLastContact": missing_last_contact,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "staleSensorCount", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )


def parse_body(input):
    """A JSON string or bytes body is parsed; anything else is returned unchanged."""
    if isinstance(input, bytes):
        input = input.decode("utf-8")
    if isinstance(input, str):
        try:
            return json.loads(input)
        except ValueError:
            return None
    return input


def unevaluated(key, reason, validation, metadata, extra=None):
    """Fail closed: the key reads None with the reason in dataCollection.errors, which Token-Service routes to
    Unevaluated (out of the score). An empty, missing or error reply is never a measured 0."""
    result = dict(extra or {})
    result[key] = None
    return create_response(result=result, validation=validation, fail_reasons=[reason], api_errors=[reason],
                           recommendations=["Confirm the NinjaOne API client can read the device inventory for this tenant."],
                           metadata=metadata)


def transform(input):
    metadata = {"transformationId": "staleSensorCount", "vendor": "NinjaOne Endpoint Management", "category": "epp"}
    try:
        return measure_stale(parse_body(input))
    except Exception as e:  # a transformation never raises into the engine
        return unevaluated("staleSensorCount", "Transformation error, so the count is unknown: " + str(e),
                           {"status": "error", "errors": [], "warnings": []}, metadata)
