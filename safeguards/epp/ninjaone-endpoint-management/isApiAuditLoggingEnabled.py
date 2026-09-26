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
        activities = data
    elif isinstance(data, dict):
        activities = data.get("activities") or data.get("data") or []
        if not isinstance(activities, list):
            activities = []
    else:
        activities = []

    total_activities = len(activities)

    admin_action_status_codes = [
        "USER_LOGGED_IN",
        "USER_LOGGED_OUT",
        "SYSTEM_REBOOTED",
        "SOFTWARE_UPDATED",
        "SOFTWARE_ADDED",
    ]

    admin_action_count = 0
    activity_type_counts = {}
    user_attributed_count = 0

    for activity in activities:
        if not isinstance(activity, dict):
            continue
        status_code = activity.get("statusCode")
        activity_type = activity.get("activityType") or "UNKNOWN"
        activity_type_counts[activity_type] = activity_type_counts.get(activity_type, 0) + 1
        if status_code in admin_action_status_codes:
            admin_action_count = admin_action_count + 1
        if activity.get("userId") is not None:
            user_attributed_count = user_attributed_count + 1

    distinct_activity_types = len(activity_type_counts)

    is_enabled = total_activities > 0 and distinct_activity_types > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        sample_types = list(activity_type_counts.keys())[:5]
        pass_reasons.append(
            "GET /v2/activities returned %d retrievable audit log entries spanning %d distinct activityType values (sample: %s), including %d records with recognizable administrative/status events (e.g. USER_LOGGED_IN, SYSTEM_REBOOTED) and %d records attributed to a userId, confirming console/API actions are recorded and retrievable."
            % (total_activities, distinct_activity_types, sample_types, admin_action_count, user_attributed_count)
        )
    else:
        fail_reasons.append(
            "GET /v2/activities returned %d activity records with %d distinct activityType values, so no retrievable administrator/technician action log evidence was found."
            % (total_activities, distinct_activity_types)
        )
        recommendations.append(
            "Verify the NinjaOne activities feed is populating for this tenant, and confirm the OAuth client has permission to read /v2/activities."
        )

    result = {
        "isApiAuditLoggingEnabled": is_enabled,
        "totalActivityRecords": total_activities,
        "distinctActivityTypes": distinct_activity_types,
        "adminActionRecordCount": admin_action_count,
        "userAttributedRecordCount": user_attributed_count,
    }

    input_summary = {
        "totalActivityRecords": total_activities,
        "distinctActivityTypes": distinct_activity_types,
        "adminActionRecordCount": admin_action_count,
    }

    metadata = {
        "transformationId": "isApiAuditLoggingEnabled",
        "vendor": "NinjaOne",
        "category": "epp",
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata=metadata,
    )
