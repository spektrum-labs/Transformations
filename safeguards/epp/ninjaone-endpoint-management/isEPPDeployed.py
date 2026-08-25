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


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}
    results = data.get("results") or []
    if not isinstance(results, list):
        results = []

    device_products = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        device_id = row.get("deviceId")
        product_name = row.get("productName")
        product_state = row.get("productState")
        if device_id is None:
            continue
        entries = device_products.get(device_id)
        if entries is None:
            entries = []
            device_products[device_id] = entries
        entries.append({"productName": product_name, "productState": product_state})

    total_devices_reporting = len(device_products)
    devices_with_active_epp = 0
    sample_products = set()
    for device_id, entries in device_products.items():
        has_active = False
        for e in entries:
            if e.get("productState") == "ON":
                has_active = True
                sample_products.add(e.get("productName"))
        if has_active:
            devices_with_active_epp = devices_with_active_epp + 1

    is_epp_deployed = total_devices_reporting > 0 and devices_with_active_epp > 0

    input_summary = {
        "totalDevicesReportingAV": total_devices_reporting,
        "devicesWithActiveEPP": devices_with_active_epp,
        "totalResultRows": len(results),
    }

    if is_epp_deployed:
        product_list = ", ".join(sorted([p for p in sample_products if p]))
        pass_reasons = [
            f"{devices_with_active_epp} of {total_devices_reporting} devices reporting to /v2/queries/antivirus-status "
            f"have at least one product with productState='ON' (products observed: {product_list}).",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        if total_devices_reporting == 0:
            fail_reasons = [
                "No devices returned any rows from /v2/queries/antivirus-status, meaning no endpoint protection "
                "product is installed and reporting on any device in this page of results.",
            ]
        else:
            fail_reasons = [
                f"{total_devices_reporting} devices reported antivirus rows but none had productState='ON', "
                "meaning no active EPP product is currently reporting.",
            ]
        recommendations = [
            "Deploy and activate an endpoint protection product (e.g. CrowdStrike Falcon Sensor or Microsoft "
            "Defender Antivirus) on the affected devices via NinjaOne policy assignment.",
        ]

    result = {
        "isEPPDeployed": is_epp_deployed,
        "totalDevicesReportingAV": total_devices_reporting,
        "devicesWithActiveEPP": devices_with_active_epp,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPDeployed",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
