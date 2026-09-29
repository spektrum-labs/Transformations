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
        events = data.get("apiResponse") or data.get("data") or data.get("results") or []
        if not isinstance(events, list):
            events = []
    else:
        events = []

    total_events = len(events)

    group_keywords = ["group_membership", "group_member", "association", "membership_change", "user_group"]

    matching_events = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        event_type = ev.get("event_type") or ""
        event_type_lower = event_type.lower() if isinstance(event_type, str) else ""
        has_association_field = isinstance(ev.get("association"), dict) and len(ev.get("association") or {}) > 0
        matches_keyword = False
        for kw in group_keywords:
            if kw in event_type_lower:
                matches_keyword = True
                break
        if matches_keyword or has_association_field:
            matching_events.append(ev)

    matching_count = len(matching_events)
    is_audited = matching_count > 0

    sample_event_types = []
    for ev in matching_events[:5]:
        et = ev.get("event_type") or "unknown"
        if et not in sample_event_types:
            sample_event_types.append(et)

    input_summary = {
        "totalEvents": total_events,
        "matchingGroupMembershipEvents": matching_count,
    }

    if is_audited:
        pass_reasons = [
            f"Found {matching_count} directory event(s) out of {total_events} total events "
            f"with group-membership/association indicators (event_type or non-empty 'association' field). "
            f"Sample event_types observed: {sample_event_types}."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"None of the {total_events} directory events returned by searchDirectoryAuditEvents in the "
            f"lookback window contained a group-membership/association event_type or a populated "
            f"'association' field, so group membership changes could not be confirmed as audited."
        ]
        recommendations = [
            "Verify that JumpCloud Directory Insights is capturing group membership change events "
            "(e.g. association_change / user_group_membership events) and that a group membership "
            "change occurred within the queried time window, then re-run this check."
        ]

    result = {
        "isGroupMembershipChangeAudited": is_audited,
        "totalEvents": total_events,
        "matchingGroupMembershipEvents": matching_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isGroupMembershipChangeAudited",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
