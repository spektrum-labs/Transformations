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

    api_errors = []
    if data.get("error") is True or data.get("statusCode") == 500:
        api_errors.append(str(data.get("errorMessage") or data.get("message") or "API error"))

    resources = data.get("resources") or []
    meta = data.get("meta") or {}
    pagination = meta.get("pagination") or {}
    total = pagination.get("total")
    if total is None:
        total = len(resources)

    is_deployed = bool(total and total > 0)

    input_summary = {"totalDevices": total, "resourcesInPage": len(resources)}

    if api_errors:
        result = {"isEPPDeployed": False, "totalDevices": 0}
        return create_response(
            result=result,
            validation=validation,
            fail_reasons=[
                "The queryDevicesScroll API call returned an error: %s. Unable to confirm sensor enrollment." % api_errors[0]
            ],
            recommendations=[
                "Verify CrowdStrike API credentials/scopes and retry the devices-scroll query to confirm sensor deployment."
            ],
            input_summary=input_summary,
            metadata={"transformationId": "isEPPDeployed", "vendor": "CrowdStrike Falcon", "category": "epp"},
            api_errors=api_errors,
        )

    result = {"isEPPDeployed": is_deployed, "totalDevices": total}

    if is_deployed:
        pass_reasons = [
            "meta.pagination.total reports %d enrolled devices in the tenant, confirming Falcon sensors are installed and reporting." % total
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "meta.pagination.total is %s, indicating no devices are currently enrolled/reporting via the Falcon sensor." % str(total)
        ]
        recommendations = [
            "Deploy the Falcon sensor to endpoints and confirm they check in via the devices-scroll query."
        ]

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isEPPDeployed", "vendor": "CrowdStrike Falcon", "category": "epp"},
    )
