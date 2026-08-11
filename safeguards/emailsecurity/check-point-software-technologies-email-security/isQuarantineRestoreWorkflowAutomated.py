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

    error_flag = data.get("error")
    status_code = data.get("statusCode")
    error_type = data.get("errorType")

    response_data = data.get("responseData")
    if response_data is None:
        response_data = {}
    if isinstance(response_data, list):
        items = response_data
    elif isinstance(response_data, dict):
        items = [response_data]
    else:
        items = []

    task_ids = [item.get("taskId") for item in items if isinstance(item, dict) and item.get("taskId")]
    entity_ids = [item.get("entityId") for item in items if isinstance(item, dict) and item.get("entityId")]

    has_task = len(task_ids) > 0

    api_errors = []
    if error_flag or status_code == 401:
        is_automated = False
        api_errors = [f"actionOnEntity returned statusCode={status_code}, errorType={error_type}"]
        pass_reasons = []
        fail_reasons = [
            f"actionOnEntity API call returned an error (statusCode={status_code}, errorType={error_type}); "
            "could not confirm a restore action was routed to an automated task queue."
        ]
        recommendations = [
            "Verify API credentials (clientId/clientSecret) are valid and scoped to the Email & Collaboration "
            "service so the actionOnEntity restore-action workflow can be confirmed via API."
        ]
    elif has_task:
        is_automated = True
        pass_reasons = [
            f"actionOnEntity returned {len(task_ids)} taskId(s) (e.g. {task_ids[0]}) for restore action(s) on "
            f"{len(entity_ids)} entity/entities, confirming the restore request was routed through an "
            "asynchronous, API-driven automation tier rather than manual admin triage of every request."
        ]
        fail_reasons = []
        recommendations = []
    else:
        is_automated = False
        pass_reasons = []
        fail_reasons = [
            "actionOnEntity response contained no responseData/taskId entries, so no automated restore task "
            "could be confirmed as queued for this tenant."
        ]
        recommendations = [
            "Confirm the quarantine restore action is invoked via POST /action/entity with an appropriate "
            "restore entityActionName and that a taskId is returned for asynchronous processing."
        ]

    result = {
        "isQuarantineRestoreWorkflowAutomated": is_automated,
        "taskCount": len(task_ids),
        "entityCount": len(entity_ids),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={"taskCount": len(task_ids), "entityCount": len(entity_ids), "statusCode": status_code},
        api_errors=api_errors,
        metadata={
            "transformationId": "isQuarantineRestoreWorkflowAutomated",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
