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
        events = data
    elif isinstance(data, dict):
        events = data.get("apiResponse") or data.get("data") or []
        if not isinstance(events, list):
            events = []
    else:
        events = []

    total_events = len(events)

    iam_event_types = set()
    admin_initiated_count = 0
    auth_events = 0
    for e in events:
        if not isinstance(e, dict):
            continue
        et = e.get("event_type")
        if et:
            iam_event_types.add(et)
        initiated_by = e.get("initiated_by")
        if isinstance(initiated_by, dict) and initiated_by.get("type") == "admin":
            admin_initiated_count = admin_initiated_count + 1
        if et and ("login" in et or "auth" in et or "password" in et or "mfa" in et):
            auth_events = auth_events + 1

    is_enabled = total_events > 0

    input_summary = {
        "totalEvents": total_events,
        "distinctEventTypes": len(iam_event_types),
        "authRelatedEvents": auth_events,
    }

    if is_enabled:
        sample_types = list(iam_event_types)[:5]
        pass_reasons = [
            f"Directory Insights /events endpoint returned {total_events} directory service audit event rows in the queried window (last 30 days).",
            f"Observed {len(iam_event_types)} distinct event_type values including {sample_types}, demonstrating IAM-relevant activity (authentications, password events, user changes) is being captured.",
            f"{auth_events} of {total_events} events relate to authentication/login/MFA/password activity, confirming IAM auth trail is logged.",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "The Directory Insights /events endpoint returned zero directory service event rows for the queried window, indicating no IAM audit trail is currently being captured or the feed is empty."
        ]
        recommendations = [
            "Verify Directory Insights is enabled for this JumpCloud organization and that admin/user authentication activity is occurring, then re-check the event feed."
        ]

    result = {
        "isIAMLoggingEnabled": is_enabled,
        "totalEvents": total_events,
        "distinctEventTypes": len(iam_event_types),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isIAMLoggingEnabled",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
