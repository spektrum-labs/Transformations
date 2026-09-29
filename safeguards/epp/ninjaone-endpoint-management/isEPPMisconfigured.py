import json
from datetime import datetime


# Endpoint rules (2026-09-29), shared by every NinjaOne antivirus-status check:
#   1. Judge a device only when its newest row is within ACTIVE_WINDOW_DAYS of the newest row
#      in the report. A device whose rows carry no timestamp is judged.
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
        results = data
    elif isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
    else:
        results = []

    if not isinstance(results, list):
        results = []

    results, scope = endpoint_rows(results, data, True)
    if scope["devicesReported"] and not scope["devicesJudged"]:
        nothing = ("Every device in the antivirus-status report was left out (stale, phone or tablet, or a Mac "
                   "whose third-party AV NinjaOne cannot read), so this is not evaluated here.")
        return create_response(result=dict(scope, isEPPMisconfigured=None), validation=validation,
                               api_errors=[nothing], fail_reasons=[nothing])
    devices = {}
    for rec in results:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        if device_id is None:
            continue
        devices.setdefault(device_id, []).append(rec)

    misconfigured_device_ids = []
    conflicting_count = 0
    missing_count = 0
    outdated_count = 0

    for device_id, records in devices.items():
        on_products = [r for r in records if r.get("productState") == "ON"]
        outdated_on_products = [r for r in on_products if r.get("definitionStatus") != "Up-to-Date"]

        device_issue = False
        if len(on_products) > 1:
            conflicting_count = conflicting_count + 1
            device_issue = True
        if len(on_products) == 0:
            missing_count = missing_count + 1
            device_issue = True
        if len(outdated_on_products) > 0:
            outdated_count = outdated_count + 1
            device_issue = True

        if device_issue:
            misconfigured_device_ids.append(device_id)

    total_devices = len(devices)
    misconfigured_count = len(misconfigured_device_ids)
    is_misconfigured = misconfigured_count > 0

    input_summary = {
        "totalDevicesObserved": total_devices,
        "misconfiguredDevices": misconfigured_count,
        "conflictingProductDevices": conflicting_count,
        "noActiveAVDevices": missing_count,
        "outdatedDefinitionDevices": outdated_count,
    }

    if is_misconfigured:
        sample_ids = misconfigured_device_ids[:5]
        fail_reasons = [
            "Found %d of %d observed devices with an AV health condition: %d with no active (ON) AV product, %d with multiple conflicting ON AV products, and %d with an active product reporting definitionStatus != 'Up-to-Date'. Sample affected deviceIds: %s"
            % (misconfigured_count, total_devices, missing_count, conflicting_count, outdated_count, sample_ids)
        ]
        pass_reasons = []
        recommendations = [
            "Review antivirus-status report for deviceIds %s and remediate: enable a single active AV product, resolve conflicting products, and update AV definitions." % sample_ids
        ]
    else:
        fail_reasons = []
        pass_reasons = [
            "All %d observed devices in the antivirus-status report have exactly one active (productState=ON) AV product with definitionStatus='Up-to-Date' and no conflicting products." % total_devices
        ]
        recommendations = []

    result = {
        **scope,
        "isEPPMisconfigured": is_misconfigured,
        "totalDevicesObserved": total_devices,
        "misconfiguredDevices": misconfigured_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPMisconfigured",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
