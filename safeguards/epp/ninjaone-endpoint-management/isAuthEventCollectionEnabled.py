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


AUTH_KEYWORDS = ["LOGIN", "LOGON", "LOGOUT", "AUTH", "SIGNIN", "SIGN_IN", "SUCCESS_AUDIT", "FAILURE_AUDIT", "SECURITY"]


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, dict) else {}

    results = data.get("results")
    if not isinstance(results, list):
        results = []

    auth_events = []
    activity_types_seen = set()
    for item in results:
        if not isinstance(item, dict):
            continue
        activity_type = item.get("activityType") or ""
        subject = item.get("subject") or ""
        message = item.get("message") or ""
        combined = f"{activity_type} {subject} {message}".upper()
        activity_types_seen.add(activity_type)
        for kw in AUTH_KEYWORDS:
            if kw in combined:
                auth_events.append(item)
                break

    total_activities = len(results)
    auth_event_count = len(auth_events)
    is_enabled = auth_event_count > 0

    input_summary = {
        "totalActivities": total_activities,
        "authEventCount": auth_event_count,
        "sampleActivityTypes": list(activity_types_seen)[:10],
    }

    if is_enabled:
        sample_types = sorted({e.get("activityType") for e in auth_events if e.get("activityType")})
        pass_reasons = [
            f"Found {auth_event_count} of {total_activities} activity records with authentication-related "
            f"activityType/subject/message content (e.g. types: {', '.join(sample_types[:5])}), confirming "
            f"NinjaOne is collecting Windows Security Success/Failure Audit login events into the Activities feed."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"No authentication-related activity records (login/logon/auth/security-audit keywords) were found "
            f"among {total_activities} activity records returned by /v2/activities."
        ]
        recommendations = [
            "Verify Login Event Auditing (Windows Security Success/Failure Audit collection) is enabled on the "
            "relevant device policies in NinjaOne, and confirm the activities feed is being populated with "
            "authentication-type events."
        ]

    result = {
        "isAuthEventCollectionEnabled": is_enabled,
        "totalActivities": total_activities,
        "authEventCount": auth_event_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isAuthEventCollectionEnabled",
            "vendor": "NinjaOne Endpoint Management",
            "category": "epp",
        },
    )
