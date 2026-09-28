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

    if isinstance(data, list):
        results = data
    elif isinstance(data, dict):
        results = data.get("results") or data.get("data") or []
    else:
        results = []

    if not isinstance(results, list):
        results = []

    device_ids_with_epp = set()
    device_ids_seen = set()
    product_names_seen = set()

    for row in results:
        if not isinstance(row, dict):
            continue
        device_id = row.get("deviceId")
        if device_id is None:
            continue
        device_ids_seen.add(device_id)
        product_name = row.get("productName") or ""
        product_state = row.get("productState") or ""
        if product_name:
            product_names_seen.add(product_name)
        if product_state == "ON":
            device_ids_with_epp.add(device_id)

    total_devices_reporting = len(device_ids_seen)
    devices_with_active_epp = len(device_ids_with_epp)

    is_epp_deployed = devices_with_active_epp > 0

    input_summary = {
        "totalAntivirusRecords": len(results),
        "totalDevicesReporting": total_devices_reporting,
        "devicesWithActiveEPP": devices_with_active_epp,
        "productNamesSeen": sorted(list(product_names_seen)),
    }

    if is_epp_deployed:
        sample_products = ", ".join(sorted(list(product_names_seen))[:3])
        pass_reasons = [
            f"Antivirus-status report returned {len(results)} product records across "
            f"{total_devices_reporting} devices; {devices_with_active_epp} devices have at "
            f"least one product with productState='ON' (e.g. {sample_products}), confirming "
            f"an EPP agent is installed and actively reporting."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Antivirus-status report returned {len(results)} records across "
            f"{total_devices_reporting} devices, but none report productState='ON'. No "
            f"evidence of an actively reporting EPP product was found."
        ]
        recommendations = [
            "Verify that an endpoint protection product (e.g. CrowdStrike Falcon Sensor, "
            "Microsoft Defender Antivirus) is installed and enabled on managed devices, and "
            "confirm the NinjaOne agent is reporting antivirus status correctly."
        ]

    result = {
        "isEPPDeployed": is_epp_deployed,
        "totalDevicesReporting": total_devices_reporting,
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
