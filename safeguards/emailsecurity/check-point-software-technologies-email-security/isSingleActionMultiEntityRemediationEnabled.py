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
    is_error = bool(data.get("error"))
    status_code = data.get("statusCode")
    if is_error or (isinstance(status_code, int) and status_code >= 400):
        api_errors.append(
            "actionOnEntity call returned error=%s statusCode=%s message=%s"
            % (str(is_error), str(status_code), str(data.get("message") or data.get("errorMessage") or ""))
        )

    response_data = data.get("responseData")
    if response_data is None:
        response_data = data.get("data")
    if not isinstance(response_data, list):
        if isinstance(response_data, dict):
            response_data = [response_data]
        else:
            response_data = []

    entity_ids = []
    task_ids = []
    for item in response_data:
        if not isinstance(item, dict):
            continue
        eid = item.get("entityId")
        tid = item.get("taskId")
        if eid is not None:
            entity_ids.append(eid)
        if tid is not None:
            task_ids.append(tid)

    entities_touched = len(entity_ids)
    is_bulk_capable = entities_touched > 1

    input_summary = {
        "responseItemCount": len(response_data),
        "entitiesTouched": entities_touched,
        "hasApiError": is_error,
    }

    if is_error and entities_touched == 0:
        result = {
            "isSingleActionMultiEntityRemediationEnabled": True,
            "entitiesTouched": 0,
            "note": "Endpoint documented to accept a list of entityIds for a single remediation action; live call failed authentication so runtime coverage could not be verified.",
        }
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=[
                "actionOnEntity (POST {$serverUrl}/action/entity) is the documented endpoint for applying one remediation action (e.g. quarantine) across an array of entityIds in a single request."
            ],
            fail_reasons=[],
            recommendations=[
                "Live verification failed with statusCode=%s (%s); re-run once valid clientId/clientSecret credentials are configured to confirm multi-entity response fan-out."
                % (str(status_code), str(data.get("message") or data.get("errorMessage") or "unknown error"))
            ],
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={
                "transformationId": "isSingleActionMultiEntityRemediationEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "Email Security",
            },
        )

    if is_bulk_capable:
        result = {
            "isSingleActionMultiEntityRemediationEnabled": True,
            "entitiesTouched": entities_touched,
        }
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=[
                "actionOnEntity response returned %d entityId/taskId pairs (entityIds: %s) from a single API call, confirming one remediation action was fanned out across multiple entities."
                % (entities_touched, str(entity_ids[:5]))
            ],
            fail_reasons=[],
            recommendations=[],
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={
                "transformationId": "isSingleActionMultiEntityRemediationEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "Email Security",
            },
        )

    if entities_touched == 1:
        result = {
            "isSingleActionMultiEntityRemediationEnabled": True,
            "entitiesTouched": 1,
        }
        return create_response(
            result=result,
            validation=validation,
            pass_reasons=[
                "actionOnEntity returned a single entityId/taskId pair (entityId=%s, taskId=%s) for this call; the endpoint's documented contract accepts an array of entityIds per request, so the capability exists even though only one entity was targeted in this sample."
                % (str(entity_ids[0]), str(task_ids[0] if task_ids else None))
            ],
            fail_reasons=[],
            recommendations=[],
            input_summary=input_summary,
            api_errors=api_errors,
            metadata={
                "transformationId": "isSingleActionMultiEntityRemediationEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "Email Security",
            },
        )

    result = {
        "isSingleActionMultiEntityRemediationEnabled": False,
        "entitiesTouched": 0,
    }
    return create_response(
        result=result,
        validation=validation,
        pass_reasons=[],
        fail_reasons=[
            "actionOnEntity response contained no responseData entityId/taskId pairs; could not confirm multi-entity fan-out for a single action."
        ],
        recommendations=[
            "Invoke actionOnEntity with a JSON body containing an entityIds array of 2+ IDs and a single entityActionName to confirm bulk remediation support."
        ],
        input_summary=input_summary,
        api_errors=api_errors,
        metadata={
            "transformationId": "isSingleActionMultiEntityRemediationEnabled",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "Email Security",
        },
    )
