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

    device_products = {}
    for rec in results:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        product_name = rec.get("productName") or ""
        if device_id is None or not product_name:
            continue
        existing = device_products.get(device_id) or []
        existing.append(product_name)
        device_products[device_id] = existing

    total_records = len(results)
    devices_with_av = len(device_products)
    is_deployed = devices_with_av > 0

    product_names = sorted(set(
        rec.get("productName") for rec in results
        if isinstance(rec, dict) and rec.get("productName")
    ))

    sample_products = ", ".join(product_names[:5]) if product_names else "none"

    if is_deployed:
        pass_reasons = [
            f"{devices_with_av} distinct device(s) reported antivirus/EPP product records "
            f"({total_records} total AV status records) via the antivirus-status query. "
            f"Detected product(s): {sample_products}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "No antivirus/EPP product records were returned by the antivirus-status report; "
            "no device appears to have an EPP product installed and reporting."
        ]
        recommendations = [
            "Verify that an endpoint protection product (e.g. Windows Defender, CrowdStrike Falcon) "
            "is installed and actively reporting status to NinjaOne on at least one managed device."
        ]

    result = {
        "isEPPDeployed": is_deployed,
        "deployedDeviceCount": devices_with_av,
        "totalAvRecords": total_records,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"totalAvRecords": total_records, "devicesWithAv": devices_with_av},
        metadata={
            "transformationId": "isEPPDeployed",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
