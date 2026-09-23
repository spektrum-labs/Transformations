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

    total_devices = len(results)
    configured_devices = 0
    unconfigured_devices = 0
    products_seen = set()

    for rec in results:
        if not isinstance(rec, dict):
            continue
        product_name = rec.get("productName") or "NONE"
        product_state = rec.get("productState")
        if product_name != "NONE" and product_state is not None:
            configured_devices = configured_devices + 1
            products_seen.add(product_name)
        else:
            unconfigured_devices = unconfigured_devices + 1

    is_configured = configured_devices > 0

    input_summary = {
        "totalDevicesReported": total_devices,
        "configuredDevices": configured_devices,
        "unconfiguredDevices": unconfigured_devices,
        "distinctProducts": list(products_seen),
    }

    metadata = {"transformationId": "isEPPConfigured", "vendor": "NinjaOne", "category": "epp"}

    if total_devices == 0:
        return create_response(
            result={"isEPPConfigured": is_configured, "configuredDevices": configured_devices, "totalDevices": total_devices},
            validation=validation,
            fail_reasons=["Antivirus status report returned no device records (results list empty); cannot confirm an EPP product is configured via policy."],
            recommendations=["Assign an endpoint protection policy to managed devices and verify the antivirus status report populates."],
            input_summary=input_summary,
            metadata=metadata,
        )

    sample_products = ", ".join(list(products_seen)) if products_seen else "unknown"

    if is_configured:
        return create_response(
            result={
                "isEPPConfigured": is_configured,
                "configuredDevices": configured_devices,
                "totalDevices": total_devices,
            },
            validation=validation,
            pass_reasons=[
                f"{configured_devices} of {total_devices} devices report a non-NONE productName with a populated productState (e.g. {sample_products}), indicating an EPP product is configured on managed devices via policy."
            ],
            input_summary=input_summary,
            metadata=metadata,
        )
    else:
        return create_response(
            result={
                "isEPPConfigured": is_configured,
                "configuredDevices": configured_devices,
                "totalDevices": total_devices,
            },
            validation=validation,
            fail_reasons=[
                f"All {total_devices} devices report productName='NONE' with no productState, indicating no endpoint protection product is configured on any managed device."
            ],
            recommendations=["Assign an endpoint protection policy (e.g. Windows Defender, Sophos) to managed devices in NinjaOne."],
            input_summary=input_summary,
            metadata=metadata,
        )
