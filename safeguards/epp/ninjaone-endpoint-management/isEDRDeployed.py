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


EDR_VENDOR_KEYWORDS = [
    "crowdstrike",
    "sentinelone",
    "sentinel one",
    "bitdefender",
    "carbon black",
    "cortex xdr",
    "cylance",
    "sophos intercept x",
    "trend micro apex one",
    "falcon",
]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}
    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    edr_products = {}
    edr_devices_on = set()
    total_devices = set()

    for row in results:
        if not isinstance(row, dict):
            continue
        device_id = row.get("deviceId")
        if device_id is not None:
            total_devices.add(device_id)
        product_name = row.get("productName") or ""
        product_state = row.get("productState") or ""
        name_lower = product_name.lower()
        is_edr = False
        for keyword in EDR_VENDOR_KEYWORDS:
            if keyword in name_lower:
                is_edr = True
                break
        if is_edr:
            edr_products[product_name] = edr_products.get(product_name, 0) + 1
            if product_state == "ON" and device_id is not None:
                edr_devices_on.add(device_id)

    total_device_count = len(total_devices)
    edr_active_count = len(edr_devices_on)
    is_edr_deployed = edr_active_count > 0

    input_summary = {
        "totalResultRows": len(results),
        "totalDevicesSeen": total_device_count,
        "edrProductNamesSeen": list(edr_products.keys()),
        "edrActiveDeviceCount": edr_active_count,
    }

    if is_edr_deployed:
        sample_products = ", ".join(list(edr_products.keys())[:3])
        pass_reasons = [
            f"Found {edr_active_count} device(s) reporting an active (productState=ON) third-party EDR "
            f"product via NinjaOne antivirus-status: {sample_products}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if edr_products:
            fail_reasons = [
                f"EDR product name(s) {', '.join(edr_products.keys())} were seen in antivirus-status "
                f"results but none report productState=ON."
            ]
            recommendations = [
                "Verify the EDR agent (e.g. CrowdStrike Falcon) is enabled and actively reporting on devices."
            ]
        else:
            fail_reasons = [
                f"No third-party EDR product (CrowdStrike, SentinelOne, Bitdefender, etc.) was found among "
                f"{len(results)} antivirus-status rows across {total_device_count} device(s)."
            ]
            recommendations = [
                "Deploy and integrate a supported third-party EDR product through NinjaOne's antivirus policy configuration."
            ]

    result = {
        "isEDRDeployed": is_edr_deployed,
        "edrActiveDeviceCount": edr_active_count,
        "totalDevicesObserved": total_device_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEDRDeployed",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
