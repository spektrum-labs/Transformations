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

    devices_with_product = set()
    product_names = set()
    total_rows = 0

    for row in results:
        if not isinstance(row, dict):
            continue
        total_rows = total_rows + 1
        device_id = row.get("deviceId")
        product_name = row.get("productName")
        if product_name:
            product_names.add(product_name)
            if device_id is not None:
                devices_with_product.add(device_id)

    is_configured = len(devices_with_product) > 0 and len(product_names) > 0

    input_summary = {
        "totalRows": total_rows,
        "devicesWithProduct": len(devices_with_product),
        "distinctProducts": len(product_names),
    }

    if is_configured:
        sample_products = sorted(list(product_names))[:5]
        pass_reasons = [
            f"Antivirus status report returned {total_rows} product rows across "
            f"{len(devices_with_product)} distinct devices, naming products such as "
            f"{', '.join(sample_products)}. This confirms an endpoint protection "
            f"product is configured to report status for devices assigned to policy."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Antivirus status report returned {total_rows} rows and "
            f"{len(devices_with_product)} devices with a named product; no EPP "
            f"product was found reporting for any device."
        ]
        recommendations = [
            "Assign an antivirus/EDR product in the device's policy Antivirus "
            "settings so that endpoint protection status is reported."
        ]

    return create_response(
        result={
            "isEPPConfigured": is_configured,
            "devicesWithProduct": len(devices_with_product),
            "distinctProducts": len(product_names),
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isEPPConfigured",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
