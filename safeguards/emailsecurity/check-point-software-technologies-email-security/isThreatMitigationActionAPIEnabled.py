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

    api_errors = []
    transformation_errors = []

    is_error = bool(data.get("error"))
    status_code = data.get("statusCode")
    error_type = data.get("errorType")
    error_message = data.get("errorMessage") or data.get("message")

    response_envelope = data.get("responseEnvelope") or {}
    response_data = data.get("responseData")

    # Normalize responseData into a list of records to inspect
    records = []
    if isinstance(response_data, list):
        records = [r for r in response_data if isinstance(r, dict)]
    elif isinstance(response_data, dict):
        records = [response_data]

    task_ids = [r.get("taskId") for r in records if r.get("taskId")]
    entity_ids = [r.get("entityId") for r in records if r.get("entityId")]

    is_enabled = False
    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_error or (isinstance(status_code, int) and status_code >= 400):
        is_enabled = False
        api_errors.append(f"actionOnEntity call failed: statusCode={status_code}, errorType={error_type}, message={error_message}")
        fail_reasons.append(
            f"actionOnEntity endpoint returned an error (statusCode={status_code}, errorType={error_type}, "
            f"message='{error_message}') rather than a taskId/entityId confirming a remediation action was accepted."
        )
        recommendations.append(
            "Verify the API credentials (clientId/clientSecret) used for the Check Point Harmony Email Security "
            "integration have permission to call POST /action/entity, then retry the remediation action call."
        )
    elif task_ids or entity_ids:
        is_enabled = True
        pass_reasons.append(
            f"POST /action/entity accepted a remediation request and returned confirmation "
            f"(taskId(s)={task_ids}, entityId(s)={entity_ids}), demonstrating that quarantine/delete/restore "
            f"actions can be triggered programmatically on flagged messages."
        )
    else:
        is_enabled = False
        fail_reasons.append(
            "actionOnEntity response contained no error but also no responseData with a taskId or entityId, "
            "so no remediation action could be confirmed as accepted by the API."
        )
        recommendations.append(
            "Invoke POST /action/entity with a valid entityActionName (e.g. quarantine, delete, restore) and "
            "entityId(s), and confirm the response includes a taskId to validate the remediation API surface."
        )

    result = {
        "isThreatMitigationActionAPIEnabled": is_enabled,
        "taskIds": task_ids,
        "entityIds": entity_ids,
    }

    input_summary = {
        "hasError": is_error,
        "statusCode": status_code,
        "recordCount": len(records),
        "taskIdCount": len(task_ids),
    }

    metadata = {
        "transformationId": "isThreatMitigationActionAPIEnabled",
        "vendor": "Check Point Software Technologies Email Security",
        "category": "emailsecurity",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
        transformation_errors=transformation_errors,
        api_errors=api_errors,
    )
