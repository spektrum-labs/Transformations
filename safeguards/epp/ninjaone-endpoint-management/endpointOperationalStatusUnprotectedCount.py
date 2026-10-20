import json
from datetime import datetime, timezone


# Endpoint rules (2026-09-29), shared by every NinjaOne antivirus-status check:
#   1. Judge a device only when its newest row is within ACTIVE_WINDOW_DAYS of the newest row
#      in the report. A device whose rows carry no timestamp is judged. If the newest row is itself
#      more than ACTIVE_WINDOW_DAYS before evaluation time, the whole fleet is dark and every device is stale.
#   2. Phones and tablets are left out (needs the device list beside the report).
#   3. A Mac whose only products are third-party ones not reporting ON is unreadable, not
#      unprotected: NinjaOne cannot read third-party AV state on macOS, so coverage there is
#      the EDR vendor's to prove. A Mac reporting productName NONE is still judged.
ACTIVE_WINDOW_DAYS = 15
FUTURE_SLACK_SECONDS = 86400  # a stamp more than a day ahead of now is a fault, not a contact
MOBILE_NODE_CLASSES = ("APPLE_IOS", "APPLE_IPADOS", "ANDROID")


def epoch(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def device_classes(data):
    """deviceId -> nodeClass from a device list riding beside the report (workflow key "devices")."""
    devices = data.get("devices") if isinstance(data, dict) else None
    if isinstance(devices, dict):
        devices = devices.get("data") or devices.get("results")
    classes = {}
    for device in devices if isinstance(devices, list) else []:
        if isinstance(device, dict) and device.get("id") is not None:
            classes[str(device.get("id"))] = str(device.get("nodeClass") or "").upper()
    return classes


def usable_row(row, need_state):
    """True when an antivirus-status row is usable evidence.

    A row must name its product, and (when the caller reads the state) state that product's state. A missing
    or null name or state is not "no product" and not OFF: it is unreadable. productName "NONE" is a real
    answer (the device has no product) and needs no state. A caller that does not read the state (the
    signature check reads definitionStatus) also accepts a row that carries a definitionStatus, with or
    without a product name: that field is the evidence it reads.
    """
    name = row.get("productName")
    named = name is not None and str(name).strip() != ""
    if not need_state:
        status = row.get("definitionStatus")
        return named or (status is not None and str(status).strip() != "")
    if not named:
        return False
    if str(name).strip().upper() == "NONE":
        return True
    state = row.get("productState")
    return state is not None and str(state).strip() != ""


def http_error_status(code):
    """The HTTP status as a number when it is an error (400 or more), else None.

    A status sent as a string ("500", " 403 ") is an error exactly like the number. A boolean, an empty or
    non-numeric string and anything below 400 are not an error status.
    """
    if isinstance(code, bool):
        return None
    if isinstance(code, str):
        code = code.strip()
        code = int(code) if code.isdecimal() else None
    if isinstance(code, int) and code >= 400:
        return code
    return None


def body_problem(input_data, data):
    """A short reason when the reply is an error rather than a measurement, else None.

    A reply that carries an error, errors, or an HTTP status of 400 or more proves nothing, even when it
    also carries product rows. It is checked on the raw reply and on the unwrapped body.
    """
    for body in (input_data, data):
        if isinstance(body, (str, bytes)):
            try:
                body = json.loads(body)
            except Exception:
                body = None
        if not isinstance(body, dict):
            continue
        err = body.get("errors") or body.get("error")
        if err:
            return "NinjaOne returned an error instead of a measurement: " + str(err)[:200]
        code = http_error_status(body.get("status_code") or body.get("statusCode") or body.get("status"))
        if code is not None:
            return "NinjaOne returned HTTP " + str(code) + " instead of a measurement."
    return None


def endpoint_rows(rows, data, mac_unreadable, need_state=True):
    """Apply the endpoint rules to antivirus-status rows. Returns (rows to judge, scope counts)."""
    classes = device_classes(data)
    by_device = {}
    for row in rows:
        if isinstance(row, dict) and row.get("deviceId") is not None:
            by_device.setdefault(str(row.get("deviceId")), []).append(row)
    # A timestamp more than FUTURE_SLACK_SECONDS ahead of now cannot be a real contact: it is a clock or data
    # fault. It is ignored for the newest-contact cutoff, so one such stamp cannot make every other device look
    # stale, and a device with no other stamp is left out as stale, never judged on it.
    ceiling = datetime.now(timezone.utc).timestamp() + FUTURE_SLACK_SECONDS
    newest = {}
    impossible = {}
    for device_id, device_rows in by_device.items():
        stamps = [epoch(r.get("timestamp")) for r in device_rows]
        stamps = [s for s in stamps if s is not None]
        usable = [s for s in stamps if s <= ceiling]
        newest[device_id] = max(usable) if usable else None
        impossible[device_id] = bool(stamps) and not usable
    known = [s for s in newest.values() if s is not None]
    cutoff = max(known) - ACTIVE_WINDOW_DAYS * 86400 if known else None
    wall_cutoff = datetime.now(timezone.utc).timestamp() - ACTIVE_WINDOW_DAYS * 86400
    dark = bool(known) and max(known) < wall_cutoff
    if dark:
        # Dark fleet: the newest check-in is itself older than the window, so every device is stale.
        cutoff = wall_cutoff
    kept = []
    stale = 0
    mobile = 0
    unreadable = 0
    unreadable_state = 0
    for device_id, device_rows in by_device.items():
        node_class = classes.get(device_id, "")
        if node_class in MOBILE_NODE_CLASSES:
            mobile = mobile + 1
            continue
        if impossible[device_id]:
            stale = stale + 1
            continue
        if cutoff is not None and newest[device_id] is not None and newest[device_id] < cutoff:
            stale = stale + 1
            continue
        readable = [r for r in device_rows if usable_row(r, need_state)]
        if not readable:
            unreadable_state = unreadable_state + 1
            continue
        if mac_unreadable and node_class == "MAC":
            named = [r for r in readable if str(r.get("productName") or "NONE").upper() != "NONE"]
            running = [r for r in readable if str(r.get("productState") or "").upper() == "ON"]
            if named and not running:
                unreadable = unreadable + 1
                continue
        kept.extend(readable)
    scope = {
        "devicesReported": len(by_device),
        "devicesJudged": len(by_device) - stale - mobile - unreadable - unreadable_state,
        "devicesLeftOutStale": stale,
        "devicesLeftOutMobile": mobile,
        "devicesLeftOutUnreadable": unreadable_state,
        "macDevicesUnreadable": unreadable,
        "activeWindowDays": ACTIVE_WINDOW_DAYS,
        "fleetDark": dark,
    }
    return kept, scope


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


def measure_unprotected(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}
    problem = body_problem(input, data)
    if problem is not None:
        return create_response(result={"endpointOperationalStatusUnprotectedCount": None}, validation=validation, api_errors=[problem], fail_reasons=[problem])

    metadata = {"transformationId": "endpointOperationalStatusUnprotectedCount", "vendor": "NinjaOne", "category": "epp"}
    key = "endpointOperationalStatusUnprotectedCount"
    if validation.get("status") == "failed":
        return unevaluated(key, "Input validation failed: the antivirus-status report did not match its schema, so "
                           "the unprotected count is unknown", validation, metadata)
    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("results") or data.get("data") or []
        if not isinstance(records, list):
            records = []
    else:
        records = []
    if not [r for r in records if isinstance(r, dict) and r.get("deviceId") is not None]:
        return unevaluated(key, "The antivirus-status report returned no device rows (empty, missing or error "
                           "reply), so the unprotected count is unknown, not 0", validation, metadata,
                           {"totalDevicesReported": 0})

    device_protected = {}
    device_seen = {}
    records, scope = endpoint_rows(records, data, True)
    if scope["devicesReported"] and not scope["devicesJudged"]:
        nothing = ("Every device in the antivirus-status report was left out (stale, phone or tablet, without a readable product state, or a Mac "
                   "whose third-party AV NinjaOne cannot read), so this is not evaluated here.")
        return create_response(result=dict(scope, endpointOperationalStatusUnprotectedCount=None), validation=validation,
                               api_errors=[nothing], fail_reasons=[nothing])
    for rec in records:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        if device_id is None:
            continue
        device_seen[device_id] = True
        product_state = rec.get("productState")
        product_name = rec.get("productName")
        is_on = product_state == "ON"
        if is_on:
            device_protected[device_id] = True
        else:
            if device_id not in device_protected:
                device_protected[device_id] = False

    total_devices = len(device_seen)
    unprotected_ids = [d for d, protected in device_protected.items() if not protected]
    unprotected_count = len(unprotected_ids)
    protected_count = total_devices - unprotected_count

    sample_ids = unprotected_ids[:10]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if total_devices == 0:
        fail_reasons.append(
            "Antivirus status report returned no device records; unable to determine unprotected endpoint count."
        )
        recommendations.append(
            "Verify the antivirus status report endpoint is returning data for managed devices."
        )
    else:
        if unprotected_count > 0:
            fail_reasons.append(
                f"{unprotected_count} of {total_devices} devices report no active AV/EPP protection "
                f"(productState != 'ON', or product missing/NONE, or state unreported); example deviceIds: {sample_ids}."
            )
            recommendations.append(
                "Investigate and remediate unprotected devices: reinstall or re-enable the endpoint protection "
                "agent and confirm productState reports 'ON'."
            )
        else:
            pass_reasons.append(
                f"All {total_devices} devices report at least one AV/EPP product with productState='ON'."
            )

    result = {
        **scope,
        "endpointOperationalStatusUnprotectedCount": unprotected_count,
        "totalDevicesReported": total_devices,
        "protectedDeviceCount": protected_count,
    }

    input_summary = {
        "recordsInResponse": len(records),
        "totalDevicesReported": total_devices,
        "unprotectedDeviceCount": unprotected_count,
    }

    metadata = {
        "transformationId": "endpointOperationalStatusUnprotectedCount",
        "vendor": "NinjaOne",
        "category": "epp",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
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
    metadata = {"transformationId": "endpointOperationalStatusUnprotectedCount", "vendor": "NinjaOne", "category": "epp"}
    try:
        return measure_unprotected(parse_body(input))
    except Exception as e:  # a transformation never raises into the engine
        return unevaluated("endpointOperationalStatusUnprotectedCount", "Transformation error, so the count is unknown: " + str(e),
                           {"status": "error", "errors": [], "warnings": []}, metadata)
