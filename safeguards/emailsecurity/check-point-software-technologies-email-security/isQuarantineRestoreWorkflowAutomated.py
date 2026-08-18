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
    if data.get("error") is True or data.get("statusCode") == 401:
        api_errors.append(
            f"API returned error: {data.get('errorMessage') or data.get('message') or 'unknown error'}"
        )

    response_data = data.get("responseData")
    if isinstance(response_data, list):
        event = response_data[0] if response_data and isinstance(response_data[0], dict) else {}
    elif isinstance(response_data, dict):
        event = response_data
    else:
        event = {}

    available_actions = event.get("availableEventActions") or []
    if not isinstance(available_actions, list):
        available_actions = []
    actions_history = event.get("actions") or []
    if not isinstance(actions_history, list):
        actions_history = []

    restore_keywords = ["restore", "autorestore", "auto-restore", "auto_restore"]

    available_lower = [str(a).lower() for a in available_actions]
    restore_available = any(
        any(kw in a for kw in restore_keywords) for a in available_lower
    )

    restore_history_items = [
        a for a in actions_history
        if isinstance(a, dict) and any(kw in str(a.get("actionType", "")).lower() for kw in restore_keywords)
    ]

    is_automated = bool(restore_available or restore_history_items)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_automated:
        if restore_available:
            pass_reasons.append(
                f"Event availableEventActions includes a restore action ({available_actions}), confirming the restore workflow is exposed via the Action API rather than manual-only admin UI triage."
            )
        if restore_history_items:
            sample = restore_history_items[0]
            pass_reasons.append(
                f"Event actions[] history records {len(restore_history_items)} restore-type action(s), e.g. actionType={sample.get('actionType')} at createTime={sample.get('createTime')}, indicating restore execution is invocable/automatable rather than requiring exclusively manual admin steps."
            )
    else:
        if api_errors:
            fail_reasons.append(
                f"Could not confirm automated restore capability: {'; '.join(api_errors)}. No event data was retrieved to inspect availableEventActions or actions history."
            )
            recommendations.append(
                "Verify API credentials (clientId/accessKey) and retry to retrieve event data with availableEventActions and actions fields."
            )
        else:
            fail_reasons.append(
                f"No restore-type action found in availableEventActions ({available_actions}) or actions history ({len(actions_history)} entries) for this event."
            )
            recommendations.append(
                "Confirm the quarantine restore action is enabled and exposed via the Event Action API (eventActionName=restore) rather than requiring manual admin triage in the portal UI."
            )

    result = {
        "isQuarantineRestoreWorkflowAutomated": is_automated,
        "availableEventActions": available_actions,
        "restoreHistoryCount": len(restore_history_items),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "eventId": event.get("eventId"),
            "availableEventActions": available_actions,
            "actionsCount": len(actions_history),
        },
        api_errors=api_errors,
        metadata={
            "transformationId": "isQuarantineRestoreWorkflowAutomated",
            "vendor": "Check Point Software Technologies Email Security",
            "category": "emailsecurity",
        },
    )
