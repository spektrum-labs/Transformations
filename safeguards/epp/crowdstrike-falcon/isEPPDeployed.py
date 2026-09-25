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

    meta = {}
    resources = []
    if isinstance(data, dict):
        meta = data.get("meta") or {}
        resources = data.get("resources") or []
    elif isinstance(data, list):
        resources = data

    pagination = meta.get("pagination") or {}
    total = pagination.get("total")
    if total is None:
        total = len(resources) if isinstance(resources, list) else 0

    is_deployed = bool(total and total > 0)

    input_summary = {
        "totalEnrolledDevices": total,
        "resourcesInPage": len(resources) if isinstance(resources, list) else 0,
    }

    if is_deployed:
        pass_reasons = [
            f"queryDevicesByFilter reports meta.pagination.total={total} enrolled Falcon sensor devices, "
            "confirming the EPP agent is installed and reporting on managed endpoints."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"queryDevicesByFilter returned meta.pagination.total={total}, indicating no enrolled Falcon "
            "sensor devices were found for this tenant."
        ]
        recommendations = [
            "Deploy the Falcon sensor to managed endpoints and confirm devices register in the Falcon console."
        ]

    result = {
        "isEPPDeployed": is_deployed,
        "totalEnrolledDevices": total,
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
            "vendor": "CrowdStrike Falcon",
            "category": "epp",
        },
    )
