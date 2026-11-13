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
        items = data
    elif isinstance(data, dict):
        items = data.get("items") or data.get("data") or []
        if not isinstance(items, list):
            items = []
    else:
        items = []

    total_records = len(items)

    auth_categories = ["logon and logoff", "authentication", "login", "log on", "log off"]
    auth_activities = ["log on", "log off", "logon", "logoff", "sign in", "sign-in", "login"]

    auth_events = []
    for item in items:
        if not isinstance(item, dict):
            continue
        category = (item.get("category") or "").strip().lower()
        activity = (item.get("activity") or "").strip().lower()
        is_auth = False
        for c in auth_categories:
            if c in category:
                is_auth = True
                break
        if not is_auth:
            for a in auth_activities:
                if a in activity:
                    is_auth = True
                    break
        if is_auth:
            auth_events.append(item)

    auth_event_count = len(auth_events)
    is_enabled = auth_event_count > 0

    successful = 0
    unsuccessful = 0
    for e in auth_events:
        result = (e.get("result") or "").strip().lower()
        if result == "successful":
            successful = successful + 1
        elif result == "unsuccessful":
            unsuccessful = unsuccessful + 1

    sample_users = []
    for e in auth_events[:5]:
        u = e.get("loggedUser")
        if u and u not in sample_users:
            sample_users.append(u)

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        pass_reasons.append(
            f"Audit log query returned {total_records} total entries, of which {auth_event_count} are "
            f"authentication events (category='Logon and Logoff' or activity='Log on'), including "
            f"{successful} successful and {unsuccessful} unsuccessful sign-in attempts, e.g. users: {sample_users}."
        )
    else:
        fail_reasons.append(
            f"Audit log query returned {total_records} total entries, but none carry a "
            "'Logon and Logoff' category or 'Log on'/'Log off' activity, so no console "
            "authentication events are being collected for this tenant."
        )
        recommendations.append(
            "Verify that Trend Micro XDR audit logging is enabled for the tenant and that the "
            "credential used has access to console sign-in / authentication events under Audit Logs."
        )

    result = {
        "isAuthEventCollectionEnabled": is_enabled,
        "totalAuditLogEntries": total_records,
        "authEventCount": auth_event_count,
        "successfulAuthEvents": successful,
        "unsuccessfulAuthEvents": unsuccessful,
    }

    input_summary = {
        "totalAuditLogEntries": total_records,
        "authEventCount": auth_event_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={"transformationId": "isAuthEventCollectionEnabled", "vendor": "Trend Micro XDR", "category": "epp"},
    )
