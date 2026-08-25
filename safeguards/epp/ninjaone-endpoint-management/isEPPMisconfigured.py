import json
from datetime import datetime


def extract_input(input_data):
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
    data = data if isinstance(data, dict) else {}
    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    devices = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        device_id = row.get("deviceId")
        if device_id is None:
            continue
        devices.setdefault(device_id, []).append(row)

    total_devices = len(devices)
    misconfigured_devices = []

    for device_id, rows in devices.items():
        active_products = [r for r in rows if str(r.get("productState") or "").upper() == "ON"]
        outdated_products = [
            r for r in rows
            if str(r.get("definitionStatus") or "").strip().lower() not in ("up-to-date", "")
        ]
        num_active = len(active_products)
        reasons_for_device = []
        if num_active == 0:
            reasons_for_device.append("no active AV product (all reporting products are not ON)")
        if num_active > 1:
            reasons_for_device.append(
                f"multiple conflicting active AV products ({num_active} products report ON)"
            )
        if outdated_products:
            names = ", ".join(sorted(set([str(r.get("productName") or "unknown") for r in outdated_products])))
            reasons_for_device.append(f"outdated AV definitions for: {names}")

        if reasons_for_device:
            misconfigured_devices.append({"deviceId": device_id, "reasons": reasons_for_device})

    misconfigured_count = len(misconfigured_devices)
    is_misconfigured = misconfigured_count > 0

    input_summary = {
        "totalDevicesObserved": total_devices,
        "misconfiguredDeviceCount": misconfigured_count,
    }

    if is_misconfigured:
        sample = misconfigured_devices[:5]
        sample_desc = "; ".join(
            [f"device {d['deviceId']}: {', '.join(d['reasons'])}" for d in sample]
        )
        pass_reasons = []
        fail_reasons = [
            f"{misconfigured_count} of {total_devices} devices observed in antivirus-status "
            f"report show an AV Health condition. Examples -- {sample_desc}."
        ]
        recommendations = [
            "Investigate and remediate flagged devices: ensure exactly one AV/EDR product "
            "reports productState=ON, update out-of-date definitions, and remove conflicting "
            "duplicate AV products.",
        ]
    else:
        pass_reasons = [
            f"All {total_devices} devices observed in antivirus-status report have exactly one "
            "active AV product reporting productState=ON with definitionStatus=Up-to-Date and no "
            "conflicting duplicate active products."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "isEPPMisconfigured": is_misconfigured,
        "totalDevicesObserved": total_devices,
        "misconfiguredDeviceCount": misconfigured_count,
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
