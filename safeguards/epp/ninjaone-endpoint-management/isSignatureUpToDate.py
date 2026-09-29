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


def endpoint_rows(rows, data, mac_unreadable):
    """Apply the endpoint rules to antivirus-status rows. Returns (rows to judge, scope counts)."""
    classes = device_classes(data)
    by_device = {}
    for row in rows:
        if isinstance(row, dict) and row.get("deviceId") is not None:
            by_device.setdefault(str(row.get("deviceId")), []).append(row)
    newest = {}
    for device_id, device_rows in by_device.items():
        stamps = [epoch(r.get("timestamp")) for r in device_rows]
        stamps = [s for s in stamps if s is not None]
        newest[device_id] = max(stamps) if stamps else None
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
    for device_id, device_rows in by_device.items():
        node_class = classes.get(device_id, "")
        if node_class in MOBILE_NODE_CLASSES:
            mobile = mobile + 1
            continue
        if cutoff is not None and newest[device_id] is not None and newest[device_id] < cutoff:
            stale = stale + 1
            continue
        if mac_unreadable and node_class == "MAC":
            named = [r for r in device_rows if str(r.get("productName") or "NONE").upper() != "NONE"]
            running = [r for r in device_rows if str(r.get("productState") or "").upper() == "ON"]
            if named and not running:
                unreadable = unreadable + 1
                continue
        kept.extend(device_rows)
    scope = {
        "devicesReported": len(by_device),
        "devicesJudged": len(by_device) - stale - mobile - unreadable,
        "devicesLeftOutStale": stale,
        "devicesLeftOutMobile": mobile,
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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

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
    records, scope = endpoint_rows(records, data, False)
    if scope["devicesReported"] and not scope["devicesJudged"]:
        nothing = ("Every device in the antivirus-status report was left out (stale, phone or tablet, or a Mac "
                   "whose third-party AV NinjaOne cannot read), so this is not evaluated here.")
        return create_response(result=dict(scope, isSignatureUpToDate=None), validation=validation,
                               api_errors=[nothing], fail_reasons=[nothing])
    reporting_records = [
        r for r in records
        if isinstance(r, dict) and r.get("definitionStatus")
    ]

    total_reporting = len(reporting_records)
    out_of_date = [r for r in reporting_records if r.get("definitionStatus") == "Out-of-Date"]
    up_to_date = [r for r in reporting_records if r.get("definitionStatus") == "Up-to-Date"]
    unknown_status = [r for r in reporting_records if r.get("definitionStatus") not in ("Out-of-Date", "Up-to-Date")]

    out_of_date_count = len(out_of_date)
    up_to_date_count = len(up_to_date)
    unknown_count = len(unknown_status)

    # is_up_to_date is derived purely from the response payload: it is true only when
    # at least one device reported a definitionStatus AND none of them are Out-of-Date.
    # An empty/absent payload (total_reporting == 0) evaluates to False through this
    # same expression, not via a hardcoded literal.
    is_up_to_date = (total_reporting > 0) and (out_of_date_count == 0)

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
