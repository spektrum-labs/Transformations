import json
from datetime import datetime


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

    if isinstance(data, dict):
        results = data.get("results") or []
    elif isinstance(data, list):
        results = data
    else:
        results = []

    if not isinstance(results, list):
        results = []

    # Group AV records per device
    devices = {}
    for rec in results:
        if not isinstance(rec, dict):
            continue
        dev_id = rec.get("deviceId")
        if dev_id is None:
            continue
        if dev_id not in devices:
            devices[dev_id] = []
        devices[dev_id].append(rec)

    total_devices = len(devices)
    misconfigured_devices = []

    for dev_id, records in devices.items():
        on_products = [r for r in records if (r.get("productState") or "").upper() == "ON"]
        outdated_products = [
            r for r in records
            if (r.get("definitionStatus") or "").lower() not in ("up-to-date", "")
        ]
        reasons_for_device = []

        if len(on_products) == 0:
            reasons_for_device.append("no active AV product (all reporting productState != ON)")
        if len(on_products) > 1:
            names = sorted({p.get("productName") or "unknown" for p in on_products})
            if len(names) > 1:
                reasons_for_device.append(
                    "multiple conflicting AV products active: " + ", ".join(names)
                )
        if len(outdated_products) > 0:
            names = sorted({p.get("productName") or "unknown" for p in outdated_products})
            reasons_for_device.append(
                "outdated AV definitions on: " + ", ".join(names)
            )

        if reasons_for_device:
            misconfigured_devices.append({
                "deviceId": dev_id,
                "reasons": reasons_for_device,
            })

    misconfigured_count = len(misconfigured_devices)
    is_misconfigured = misconfigured_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_misconfigured:
        sample = misconfigured_devices[:5]
        sample_desc = "; ".join(
            f"deviceId={d['deviceId']} ({', '.join(d['reasons'])})" for d in sample
        )
        fail_reasons.append(
            f"{misconfigured_count} of {total_devices} devices scanned have an AV health "
            f"condition triggered. Examples: {sample_desc}."
        )
        recommendations.append(
            "Investigate and remediate the flagged devices: enable a single consistent AV "
            "product, disable redundant/conflicting products (e.g. Windows Defender when a "
            "third-party EPP such as CrowdStrike Falcon is the primary), and force a "
            "definitions update on any device reporting outdated signatures."
        )
    else:
        pass_reasons.append(
            f"All {total_devices} devices with antivirus-status records report exactly one "
            f"active (productState=ON) AV product with up-to-date definitions; no missing, "
            f"disabled, outdated, or conflicting AV conditions were found."
        )

    result = {
        "isEPPMisconfigured": is_misconfigured,
        "misconfiguredDeviceCount": misconfigured_count,
        "totalDevicesScanned": total_devices,
    }

    input_summary = {
        "totalAvRecords": len(results),
        "totalDevicesScanned": total_devices,
        "misconfiguredDeviceCount": misconfigured_count,
    }

    metadata = {
        "transformationId": "isEPPMisconfigured",
        "vendor": "NinjaOne Endpoint Management",
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
