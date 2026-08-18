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
    if data.get("error") or data.get("errorType") == "authentication" or data.get("statusCode") == 401:
        api_errors.append(f"API error: {data.get('errorMessage') or data.get('message') or 'unknown error'}")
        return create_response(
            result={"isPostDeliveryQuarantineEnabled": False},
            validation=validation,
            fail_reasons=["Could not retrieve event data from getEventById due to an API/authentication error; unable to confirm post-delivery quarantine capability."],
            recommendations=["Verify the clientId/accessKey credentials used to call the Event API and retry."],
            input_summary={"error": True},
            api_errors=api_errors,
            metadata={
                "transformationId": "isPostDeliveryQuarantineEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )

    response_data = data.get("responseData")
    if isinstance(response_data, list):
        event = response_data[0] if response_data else {}
    elif isinstance(response_data, dict):
        event = response_data
    else:
        event = {}

    if not isinstance(event, dict):
        event = {}

    state = event.get("state") or ""
    available_actions = event.get("availableEventActions") or []
    if not isinstance(available_actions, list):
        available_actions = []
    actions = event.get("actions") or []
    if not isinstance(actions, list):
        actions = []

    available_actions_lower = [str(a).lower() for a in available_actions]
    quarantine_available = any("quarantine" in a for a in available_actions_lower)

    state_is_quarantined = str(state).lower() == "quarantined"

    quarantine_action_taken = False
    for act in actions:
        if isinstance(act, dict):
            action_type = str(act.get("actionType") or "").lower()
            if "quarantine" in action_type:
                quarantine_action_taken = True
                break

    is_enabled = bool(quarantine_available or state_is_quarantined or quarantine_action_taken)

    input_summary = {
        "eventId": event.get("eventId"),
        "state": state,
        "availableEventActions": available_actions,
        "actionsCount": len(actions),
    }

    if is_enabled:
        pass_reasons = []
        if quarantine_available:
            pass_reasons.append(
                f"Event availableEventActions includes a quarantine action: {available_actions}."
            )
        if state_is_quarantined:
            pass_reasons.append(
                f"Event state is 'quarantined' (eventId={event.get('eventId')}), confirming a message was retroactively quarantined post-delivery."
            )
        if quarantine_action_taken:
            pass_reasons.append(
                f"actions[] history for eventId={event.get('eventId')} contains a completed quarantine actionType, evidencing post-delivery quarantine execution."
            )
        return create_response(
            result={"isPostDeliveryQuarantineEnabled": True},
            validation=validation,
            pass_reasons=pass_reasons,
            input_summary=input_summary,
            metadata={
                "transformationId": "isPostDeliveryQuarantineEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )
    else:
        return create_response(
            result={"isPostDeliveryQuarantineEnabled": False},
            validation=validation,
            fail_reasons=[
                f"Event state='{state}' and availableEventActions={available_actions} show no quarantine capability or quarantine action recorded in actions[]."
            ],
            recommendations=[
                "Confirm the Event API is returning full event detail including availableEventActions, and that the tenant's mitigation policy exposes a 'quarantine' action for post-delivery malicious verdicts."
            ],
            input_summary=input_summary,
            metadata={
                "transformationId": "isPostDeliveryQuarantineEnabled",
                "vendor": "Check Point Software Technologies Email Security",
                "category": "emailsecurity",
            },
        )
