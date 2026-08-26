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
        devices = data
    elif isinstance(data, dict):
        devices = data.get("data") or data.get("results") or []
    else:
        devices = []

    total_devices = len(devices)

    approved_count = 0
    communicating_count = 0
    sample_names = []

    for d in devices:
        if not isinstance(d, dict):
            continue
        approval = d.get("approvalStatus")
        if approval == "APPROVED":
            approved_count = approved_count + 1
        last_contact = d.get("lastContact")
        if approval == "APPROVED" and last_contact:
            communicating_count = communicating_count + 1
            if len(sample_names) < 3:
                sample_names.append(d.get("systemName") or str(d.get("id")))

    is_deployed = communicating_count > 0

    input_summary = {
        "totalDevices": total_devices,
        "approvedDevices": approved_count,
        "communicatingDevices": communicating_count,
    }

    if is_deployed:
        sample_str = ", ".join(sample_names) if sample_names else "none"
        pass_reasons = [
            f"{communicating_count} of {total_devices} devices report approvalStatus=APPROVED "
            f"with a non-null lastContact timestamp, indicating the NinjaOne agent is installed "
            f"and actively communicating (e.g. {sample_str})."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_devices} devices returned by getDevicesDetailed report both "
            f"approvalStatus=APPROVED and a non-null lastContact timestamp."
        ]
        recommendations = [
            "Verify the NinjaOne agent installer has been deployed to endpoints and that devices "
            "are approved in the console (Administration > Devices > Approval)."
        ]

    result = {
        "isAgentDeployed": is_deployed,
        "totalDevices": total_devices,
        "approvedDevices": approved_count,
        "communicatingDevices": communicating_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAgentDeployed",
            "vendor": "NinjaOne",
            "category": "epp",
        },
    )
