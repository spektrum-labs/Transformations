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
        keys = data
    elif isinstance(data, dict):
        keys = data.get("apiResponse") or data.get("data") or []
        if not isinstance(keys, list):
            keys = []
    else:
        keys = []

    named_keys = [k for k in keys if isinstance(k, dict) and k.get("name")]
    connector_count = len(named_keys)
    is_enabled = connector_count > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        names = ", ".join([k.get("name", "unknown") for k in named_keys])
        pass_reasons.append(
            f"Found {connector_count} Azure cloud connector(s) configured in listAzureKeys: {names}. "
            "This confirms cloud asset discovery via a dedicated Azure connector, not just DNS-based enumeration."
        )
    else:
        fail_reasons.append(
            "No Azure cloud connectors were returned by listAzureKeys (business/azure-keys), "
            "indicating no dedicated cloud connector is configured for this tenant."
        )
        recommendations.append(
            "Configure a dedicated cloud connector (AWS, Azure, or GCP) under ASM Manage Integrations "
            "to enable cloud-native asset discovery beyond DNS-based enumeration."
        )

    return create_response(
        result={
            "isCloudAssetDiscoveryEnabled": is_enabled,
            "cloudConnectorCount": connector_count,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"cloudConnectorCount": connector_count},
        metadata={
            "transformationId": "isCloudAssetDiscoveryEnabled",
            "vendor": "Tenable Attack Surface Management",
            "category": "asm",
        },
    )
