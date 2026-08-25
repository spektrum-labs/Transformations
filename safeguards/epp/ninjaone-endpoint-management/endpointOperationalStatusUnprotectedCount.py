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

    device_states = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        device_id = row.get("deviceId")
        if device_id is None:
            continue
        state = row.get("productState")
        is_on = isinstance(state, str) and state.strip().upper() == "ON"
        current = device_states.get(device_id, False)
        device_states[device_id] = current or is_on

    total_devices = len(device_states)
    unprotected_ids = [dev for dev, protected in device_states.items() if not protected]
    unprotected_count = len(unprotected_ids)

    input_summary = {
        "totalDevicesReporting": total_devices,
        "unprotectedDeviceCount": unprotected_count,
        "totalAvRecords": len(results),
    }

    if total_devices == 0:
        pass_reasons = []
        fail_reasons = []
        recommendations = ["No antivirus-status records were returned; verify the antivirus-status query is returning data for this tenant."]
        additional_findings = ["Antivirus status report returned zero device records."]
    else:
        sample_unprotected = unprotected_ids[:5]
        if unprotected_count > 0:
            pass_reasons = []
            fail_reasons = [
                f"{unprotected_count} of {total_devices} devices reporting to the antivirus-status query have no product with productState='ON' (sample deviceIds: {sample_unprotected})."
            ]
            recommendations = [
                "Investigate the listed unprotected deviceIds and deploy or re-enable an antivirus/EPP product on them."
            ]
            additional_findings = []
        else:
            pass_reasons = [
                f"All {total_devices} devices reporting to the antivirus-status query have at least one product with productState='ON'."
            ]
            fail_reasons = []
            recommendations = []
            additional_findings = []

    result = {
        "endpointOperationalStatusUnprotectedCount": unprotected_count,
        "totalDevicesReporting": total_devices,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        additional_findings=additional_findings,
        metadata={
            "transformationId": "endpointOperationalStatusUnprotectedCount",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
