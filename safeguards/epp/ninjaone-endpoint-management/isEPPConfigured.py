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
        if not isinstance(results, list):
            results = []
    else:
        results = []

    total_records = len(results)

    devices_with_product = {}
    for rec in results:
        if not isinstance(rec, dict):
            continue
        device_id = rec.get("deviceId")
        product_name = rec.get("productName")
        product_state = rec.get("productState")
        if device_id is None:
            continue
        has_product = bool(product_name) and product_state is not None
        if device_id not in devices_with_product:
            devices_with_product[device_id] = False
        if has_product:
            devices_with_product[device_id] = True

    total_devices = len(devices_with_product)
    configured_devices = sum(1 for v in devices_with_product.values() if v)

    is_epp_configured = total_records > 0 and configured_devices > 0

    product_names_seen = sorted(list({
        rec.get("productName") for rec in results
        if isinstance(rec, dict) and rec.get("productName")
    }))

    input_summary = {
        "totalRecords": total_records,
        "totalDevices": total_devices,
        "configuredDevices": configured_devices,
        "productNamesSeen": product_names_seen,
    }

    if is_epp_configured:
        sample_products = ", ".join(product_names_seen[:3]) if product_names_seen else "unknown product"
        pass_reasons = [
            f"Antivirus status report returned {total_records} records across {total_devices} devices, "
            f"with {configured_devices} devices reporting a configured AV product (e.g. {sample_products}). "
            f"This confirms an endpoint protection product is configured to report status for the assigned policy."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Antivirus status report returned {total_records} records across {total_devices} devices, "
            f"but no device reported a non-empty productName with a productState value, indicating no "
            f"endpoint protection product is configured to report on the assigned policy."
        ]
        recommendations = [
            "Assign an antivirus/EPP policy (e.g. Windows Defender, CrowdStrike Falcon) to the affected "
            "devices' NinjaOne policy so it reports into the antivirus status report."
        ]

    return create_response(
        result={
            "isEPPConfigured": is_epp_configured,
            "totalDevices": total_devices,
            "configuredDevices": configured_devices,
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
