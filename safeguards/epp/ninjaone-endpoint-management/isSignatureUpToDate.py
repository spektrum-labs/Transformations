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
    """Extract data and validation from input, handling enriched + legacy formats."""
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


def transform_report(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}
    problem = body_problem(input, data)
    if problem is not None:
        return create_response(result={"isSignatureUpToDate": None}, validation=validation, api_errors=[problem], fail_reasons=[problem])

    if isinstance(data, list):
        records = data
    elif isinstance(data, dict):
        records = data.get("results") or data.get("data") or []
        if not isinstance(records, list):
            records = []
    else:
        records = []

    # Only consider devices that have an actual AV product reporting a definitionStatus.
    # Devices with productName == "NONE" have no AV product installed and carry no
    # definitionStatus field at all - they are excluded from this signature-currency check.
    records, scope = endpoint_rows(records, data, False, False)
    if not scope["devicesJudged"]:
        nothing = ("Every device in the antivirus-status report was left out (stale, phone or tablet, without a readable product state, or a Mac "
                   "whose third-party AV NinjaOne cannot read), so this is not evaluated here.")
        if not scope["devicesReported"]:
            nothing = "NinjaOne returned no antivirus-status rows for any device, so there is nothing to judge and this is not evaluated here."
        return create_response(result=dict(scope, isSignatureUpToDate=None), validation=validation,
                               api_errors=[nothing], fail_reasons=[nothing])
    reporting_records = [
        r for r in records
        if isinstance(r, dict) and str(r.get("definitionStatus") or "").strip()
    ]

    total_reporting = len(reporting_records)
    if not total_reporting:
        # No device reports a definitionStatus. When a judged device has a named product, that product did not say
        # whether its signatures are current: signature currency cannot be confirmed, which is Not evaluated, not a fail.
        # A fleet where no device has a product at all (productName NONE) stays as before.
        named = [r for r in records if isinstance(r, dict) and str(r.get("productName") or "").strip().upper() not in ("", "NONE")]
        if named:
            nothing = ("The antivirus products on the judged devices did not report a definition status, so signature "
                       "currency cannot be confirmed and this is not evaluated here.")
            return create_response(result=dict(scope, isSignatureUpToDate=None), validation=validation,
                                   api_errors=[nothing], fail_reasons=[nothing],
                                   recommendations=["Verify that the antivirus products report their definition status to NinjaOne."])
    out_of_date = [r for r in reporting_records if status_kind(r.get("definitionStatus")) == "out"]
    up_to_date = [r for r in reporting_records if status_kind(r.get("definitionStatus")) == "up"]
    unknown_status = [r for r in reporting_records if status_kind(r.get("definitionStatus")) is None]

    out_of_date_count = len(out_of_date)
    up_to_date_count = len(up_to_date)
    unknown_count = len(unknown_status)

    if total_reporting > 0 and up_to_date_count == 0 and out_of_date_count == 0:
        # Every reporting device says "Unknown" (or any status that is neither Up-to-Date nor Out-of-Date). No product has
        # said its signatures are current, so nothing here shows they are: Not evaluated, never a pass.
        nothing = ("Every device reporting a definition status reports Unknown (%d of %d), and none reports Up-to-Date, so "
                   "signature currency cannot be confirmed and this is not evaluated here." % (unknown_count, total_reporting))
        return create_response(result=dict(scope, isSignatureUpToDate=None, totalReportingDevices=total_reporting,
                                           outOfDateCount=0, upToDateCount=0, unknownStatusCount=unknown_count),
                               validation=validation, api_errors=[nothing], fail_reasons=[nothing],
                               recommendations=["Verify that the antivirus products report a definition status of Up-to-Date to NinjaOne."])

    # is_up_to_date is derived purely from the response payload: it is true only when
    # at least one device reported Up-to-Date AND none of them are Out-of-Date.
    # An empty/absent payload (total_reporting == 0) evaluates to False through this
    # same expression, not via a hardcoded literal.
    is_up_to_date = (up_to_date_count > 0) and (out_of_date_count == 0)

    device_ids_out_of_date = [r.get("deviceId") for r in out_of_date]

    result = {
        **scope,
        "isSignatureUpToDate": is_up_to_date,
        "totalReportingDevices": total_reporting,
        "outOfDateCount": out_of_date_count,
        "upToDateCount": up_to_date_count,
        "unknownStatusCount": unknown_count,
    }

    if total_reporting == 0:
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=["No antivirus-status records with a definitionStatus field were returned; signature currency cannot be confirmed."],
            recommendations=["Verify that AV products deployed on endpoints are reporting definition status to the antivirus-status report."],
            input_summary={"totalRecords": len(records), "totalReportingDevices": 0},
            metadata={"transformationId": "isSignatureUpToDate", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
        )

    if is_up_to_date:
        pass_reasons = [
            f"All {total_reporting} devices reporting a definitionStatus show no 'Out-of-Date' AV signatures "
            f"({up_to_date_count} Up-to-Date, {unknown_count} Unknown)."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"{out_of_date_count} of {total_reporting} devices report definitionStatus='Out-of-Date' "
            f"(deviceIds: {device_ids_out_of_date})."
        ]
        recommendations = [
            "Force an antivirus signature/definition update on the listed devices, or investigate why "
            "their AV product is failing to update definitions."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalRecords": len(records), "totalReportingDevices": total_reporting,
                       "outOfDateCount": out_of_date_count, "upToDateCount": up_to_date_count},
        metadata={"transformationId": "isSignatureUpToDate", "vendor": "NinjaOne Endpoint Management", "category": "epp"},
    )


ANSWER_KEY = "isSignatureUpToDate"
AT_LEAST_KEY = "outOfDateCount"


def proven_by_a_seen_row(result):
    return result.get(ANSWER_KEY) is False and (result.get("outOfDateCount") or 0) > 0


def status_kind(value):
    """"up" for Up-to-Date, "out" for Out-of-Date, else None, whatever the case, spacing or hyphenation."""
    text = "".join([ch for ch in str(value or "").lower() if ch.isalnum()])
    if text == "uptodate":
        return "up"
    if text == "outofdate":
        return "out"
    return None


# A report that holds fewer rows than the vendor says exist is only part of the fleet. A verdict that rests on the ABSENCE
# of a row (no Out-of-Date device, no device left off, no misconfigured device, no active product) is not proven by the
# rows that were read, so it reads None. A verdict that a row which WAS read proves stays, with its counts left unknown.
PARTIAL_REASON = ("The NinjaOne antivirus-status report is only part of the fleet (a cursor count or a next-page marker "
                  "shows rows that were not read), so a verdict that rests on the rows that were not seen is not proven "
                  "and this is not evaluated here.")
PARTIAL_NOTE = ("The antivirus-status report is only part of the fleet. This verdict is proven by a row that was read; the "
                "counts are unknown because the unread rows are not counted.")
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

    A next-page marker or a more-pages flag that is set, a cursor.count above the rows received, a cursor that names
    itself but gives no count (it cannot show the read is whole), or a cursor that is a set value. The live joined body
    has "cursor": [] and no marker, which is a complete read.
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
        if count is None and marker_set(cursor.get("name")):
            return True
        for key in NEXT_KEYS + MORE_KEYS:
            if marker_set(cursor.get(key)):
                return True
    elif marker_set(cursor):
        return True
    return False


def report_rows(data):
    """The rows the report carries, as received."""
    if isinstance(data, dict):
        rows = data.get("results") or data.get("data") or []
        return rows if isinstance(rows, list) else []
    return data if isinstance(data, list) else []


def partial_answer(answer, validation):
    """The answer for a partial report: a verdict a seen row proves stays (counts unknown), any other verdict reads None."""
    result = answer["transformedResponse"]
    if proven_by_a_seen_row(result):
        lower_bound = result.get(AT_LEAST_KEY) if AT_LEAST_KEY else None
        for name in list(result.keys()):
            found = result.get(name)
            if name != ANSWER_KEY and isinstance(found, int) and not isinstance(found, bool):
                result[name] = None
        result["partialRead"] = True
        if AT_LEAST_KEY:
            result[AT_LEAST_KEY + "AtLeast"] = lower_bound
        answer["additionalInfo"]["evaluation"]["additionalFindings"] = [PARTIAL_NOTE]
        return answer
    return create_response(result={ANSWER_KEY: None, "partialRead": True}, validation=validation,
                           api_errors=[PARTIAL_REASON], fail_reasons=[PARTIAL_REASON])


def transform(input):
    answer = transform_report(input)
    result = answer.get("transformedResponse")
    if not isinstance(result, dict) or result.get(ANSWER_KEY) is None:
        return answer
    data, validation = extract_input(input)
    if not shows_more_rows(data, len(report_rows(data))):
        return answer
    return partial_answer(answer, validation)
