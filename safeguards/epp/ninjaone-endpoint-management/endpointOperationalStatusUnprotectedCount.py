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


def device_roster(data):
    """The device list riding beside the report (workflow key "devices") as a list, or None when it is absent or unreadable.

    The list is the roster the result is measured against. A missing key, a value that is not a list, an error
    reply (an error or errors field, or an HTTP status of 400 or more) and a wrapper with no list inside are all
    unreadable. A well-formed empty list is readable.
    """
    devices = data.get("devices") if isinstance(data, dict) else None
    if isinstance(devices, dict):
        if devices.get("error") or devices.get("errors"):
            return None
        if http_error_status(devices.get("status_code") or devices.get("statusCode") or devices.get("status")) is not None:
            return None
        for key in ("data", "results"):
            if isinstance(devices.get(key), list):
                return devices.get(key)
        return None
    return devices if isinstance(devices, list) else None


def report_window_start(rows):
    """The earliest last contact that still counts as active, the same cutoff endpoint_rows applies to report rows.

    It is ACTIVE_WINDOW_DAYS before the newest usable row timestamp, or before now when that newest row is itself
    older than the window (a dark fleet). A timestamp more than FUTURE_SLACK_SECONDS ahead of now is a fault and is
    ignored. With no usable timestamp it is ACTIVE_WINDOW_DAYS before now.
    """
    now = datetime.now(timezone.utc).timestamp()
    wall = now - ACTIVE_WINDOW_DAYS * 86400
    stamps = [epoch(r.get("timestamp")) for r in rows if isinstance(r, dict) and r.get("deviceId") is not None]
    stamps = [s for s in stamps if s is not None and s <= now + FUTURE_SLACK_SECONDS]
    if not stamps or max(stamps) < wall:
        return wall
    return max(stamps) - ACTIVE_WINDOW_DAYS * 86400


def devices_without_report(devices, rows):
    """Devices in the device list (workflow key "devices") that the antivirus-status report does not mention.

    A device the report does not mention is not shown protected: it counts against the result and never for it
    (missing is never a pass). Phones and tablets, and devices not seen within ACTIVE_WINDOW_DAYS (or with a
    last contact more than a day ahead of now), are left out as in the other endpoint rules. `rows` is every
    report row before the endpoint rules run, so a device whose rows were left out is not also counted as missing.
    `devices` is the roster from device_roster. Returns (devices counted as not covered, devices left out).
    """
    reported = set()
    for row in rows:
        if isinstance(row, dict) and row.get("deviceId") is not None:
            reported.add(str(row.get("deviceId")))
    now = datetime.now(timezone.utc).timestamp()
    window_start = report_window_start(rows)
    seen_ids = set()
    counted = 0
    left_out = 0
    for device in devices:
        if not isinstance(device, dict) or device.get("id") is None:
            continue
        device_id = str(device.get("id"))
        if device_id in reported or device_id in seen_ids:
            continue
        seen_ids.add(device_id)
        if str(device.get("nodeClass") or "").upper() in MOBILE_NODE_CLASSES:
            left_out = left_out + 1
            continue
        last_contact = epoch(device.get("lastContact"))
        if last_contact is not None and (last_contact < window_start or last_contact > now + FUTURE_SLACK_SECONDS):
            left_out = left_out + 1
            continue
        counted = counted + 1
    return counted, left_out


# A read that holds fewer rows than the vendor says exist is only part of the fleet. The devices on the pages nobody read
# are unseen, not "missing", so a percentage or a total taken from the part that was read is not a total.
PARTIAL_REASON = ("The NinjaOne antivirus-status report or the device list is only part of the fleet (a cursor count or a "
                  "next-page marker shows rows that were not read), so a figure taken from the part that was read is not a "
                  "total and this is not evaluated here.")
NEXT_KEYS = ("next", "nextPage", "nextToken", "nextCursor", "nextKey", "nextUrl", "nextLink", "nextOffset",
             "next_page", "next_token", "next_cursor", "next_key", "next_url", "next_link", "next_offset")
MORE_KEYS = ("truncated", "hasMore", "has_more", "hasNext", "has_next", "moreResults", "more_results", "more")


def count_of(value):
    """An integer count, or None. Stored replays stringify numbers."""
    if isinstance(value, bool):
        return None
    try:
        return int(str(value).strip())
    except Exception:
        return None


def marker_set(value):
    """True when a pagination cursor or more-pages flag carries a value. Stored replays stringify null and false."""
    if value is None or value is False:
        return False
    if isinstance(value, (list, dict, tuple)):
        return len(value) > 0
    return str(value).strip().lower() not in ("", "none", "null", "false", "0")


def shows_more_rows(body, received):
    """True when a body that carries rows says there are more rows than it holds.

    A next-page marker or a more-pages flag that is set, a cursor that is set, or a cursor.count above the rows received.
    The live joined body has "cursor": [] and no marker, which is a complete read.
    """
    if not isinstance(body, dict):
        return False
    for key in NEXT_KEYS + MORE_KEYS:
        if marker_set(body.get(key)):
            return True
    cursor = body.get("cursor")
    if isinstance(cursor, dict):
        count = count_of(cursor.get("count"))
        if count is not None and count > received:
            return True
        for key in NEXT_KEYS + MORE_KEYS:
            if marker_set(cursor.get(key)):
                return True
    elif marker_set(cursor):
        return True
    return False


def partial_read(data, report_rows, roster):
    """PARTIAL_REASON when the report or the device list (workflow key "devices") is only part of the fleet, else None.

    `report_rows` is every report row received and `roster` is the device list from device_roster. A device-list wrapper
    that carries a next-page marker or a cursor.count above its list is partial; a plain list cannot say.
    """
    if shows_more_rows(data, len(report_rows)):
        return PARTIAL_REASON
    wrapper = data.get("devices") if isinstance(data, dict) else None
    if isinstance(wrapper, dict) and shows_more_rows(wrapper, len(roster)):
        return PARTIAL_REASON
    return None


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
    roster = device_roster(data)
    if roster is None:
        return unevaluated(key, "The NinjaOne device list was not returned or could not be read, so devices the antivirus-status report does not mention cannot be counted and this is not evaluated here.", validation, metadata,
                           {"deviceListRead": False})
    partial = partial_read(data, records, roster)
    if partial is not None:
        return partial_count(key, partial, endpoint_rows(records, data, True), validation, metadata)
    device_seen = {}
    report_rows = records
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

    # A device in the device list that the report does not mention is not shown protected: it counts as unprotected.
    missing, missing_left_out = devices_without_report(roster, report_rows)
    reporting = len(device_seen)
    total_devices = reporting + missing
    unprotected_ids = [d for d, protected in device_protected.items() if not protected]
    unprotected_count = len(unprotected_ids) + missing
    protected_count = reporting - len(unprotected_ids)

    sample_ids = unprotected_ids[:10]

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if unprotected_count > 0:
        fail_reasons.append(
            f"{unprotected_count} of {total_devices} devices report no active AV/EPP protection "
            f"(productState != 'ON', or product missing/NONE, or state unreported); example deviceIds: {sample_ids}."
        )
        recommendations.append(
            "Investigate and remediate unprotected devices: reinstall or re-enable the endpoint protection "
            "agent and confirm productState reports 'ON'."
        )
        if missing:
            fail_reasons.append("%d devices in the device list have no antivirus-status row, so they count as unprotected." % missing)
    else:
        pass_reasons.append(
            f"All {total_devices} devices report at least one AV/EPP product with productState='ON'."
        )

    result = {
        **scope,
        "endpointOperationalStatusUnprotectedCount": unprotected_count,
        "totalDevicesReported": reporting,
        "totalDevices": total_devices,
        "protectedDeviceCount": protected_count,
        "devicesNotInReport": missing,
        "devicesNotInReportLeftOut": missing_left_out,
        "deviceListRead": True,
    }

    input_summary = {
        "recordsInResponse": len(records),
        "totalDevicesReported": reporting,
        "totalDevices": total_devices,
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


def partial_count(key, partial, judged, validation, metadata):
    """The count when only part of the fleet was read: not a total, so it reads None.

    A seen unprotected device is unprotected whatever the unread pages hold, but a floor is not a count: it can grade a pass
    against any threshold above zero (3 seen, a limit of 5, a real count of 10). So the criterion key is None with a
    data-collection error, and the number of seen unprotected devices is reported beside it as unprotectedCountAtLeast.
    Devices the report does not mention are not added: on a partial read they may be on the unread rows.
    """
    rows, scope = judged
    protected = {}
    for rec in rows:
        if not isinstance(rec, dict) or rec.get("deviceId") is None:
            continue
        if rec.get("productState") == "ON":
            protected[rec.get("deviceId")] = True
        elif rec.get("deviceId") not in protected:
            protected[rec.get("deviceId")] = False
    seen_off = [d for d, covered in protected.items() if not covered]
    return unevaluated(key, partial, validation, metadata,
                       {"totalDevices": None, "partialRead": True, "unprotectedCountAtLeast": len(seen_off)})


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
