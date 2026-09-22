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

    devices = data.get("devices")
    if not isinstance(devices, list):
        devices = []

    # ``count`` is the fleet-wide total; ``devices`` is only the page we were
    # served. Trusting len(devices) understates the fleet whenever the response
    # is truncated (Lookout defaults to 100 per page, max 1000).
    reported_count_field = data.get("count")
    total_devices = reported_count_field if isinstance(reported_count_field, int) else len(devices)

    mdm_managed_count = 0
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        mdm_type = dev.get("mdm_type")
        details = dev.get("details") or {}
        connector_id = details.get("mdm_connector_id") if isinstance(details, dict) else None
        connector_uuid = details.get("mdm_connector_uuid") if isinstance(details, dict) else None
        if mdm_type or connector_id or connector_uuid:
            mdm_managed_count = mdm_managed_count + 1

    sampled_devices = len(devices)
    is_mdm_managed = mdm_managed_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if sampled_devices == 0:
        fail_reasons.append("No device records were present in the API response to evaluate MDM enrollment.")
        recommendations.append("Verify the Lookout MES devices endpoint is returning device inventory data.")
        is_mdm_managed = False
    elif is_mdm_managed:
        pass_reasons.append(
            f"{mdm_managed_count} of {sampled_devices} sampled devices report MDM connector metadata "
            f"(mdm_type / mdm_connector_id / mdm_connector_uuid in the 'details' block), indicating active "
            f"MDM/UEM integration with Lookout (e.g. mdm_type='INTUNE' with mdm_connector_id set)."
        )
    else:
        fail_reasons.append(
            f"None of the {sampled_devices} sampled devices report MDM connector metadata "
            f"(mdm_type, mdm_connector_id, mdm_connector_uuid all absent)."
        )
        recommendations.append(
            "Connect an MDM/UEM console (e.g. Intune, Workspace ONE) to the Lookout MES tenant so devices "
            "report mdm_type and mdm_connector_id/uuid fields."
        )

    result = {
        "isMdmManaged": is_mdm_managed,
        "mdmManagedDeviceCount": mdm_managed_count,
        "sampledDeviceCount": sampled_devices,
        "totalDeviceCount": total_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "sampledDeviceCount": sampled_devices,
            "mdmManagedDeviceCount": mdm_managed_count,
            "totalDeviceCount": total_devices,
        },
        metadata={
            "transformationId": "isMdmManaged",
            "vendor": "Lookout",
            "category": "mobile-security",
        },
    )
