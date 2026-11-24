
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
        items = data
    elif isinstance(data, dict):
        items = data.get("items") or data.get("data") or []
    else:
        items = []

    total = len(items)

    admin_categories = set()
    api_key_events = 0
    logon_events = 0
    other_admin_events = 0

    for entry in items:
        if not isinstance(entry, dict):
            continue
        category = entry.get("category") or ""
        activity = entry.get("activity") or ""
        admin_categories.add(category)
        if category == "API Keys":
            api_key_events = api_key_events + 1
        elif category in ("Logon and Logoff",):
            logon_events = logon_events + 1
        else:
            other_admin_events = other_admin_events + 1

    is_enabled = total > 0

    pass_reasons = []
    fail_reasons = []
    recommendations = []

    if is_enabled:
        cats = ", ".join(sorted([c for c in admin_categories if c]))
        pass_reasons.append(
            f"Audit log endpoint returned {total} administrative/API action records "
            f"spanning categories: {cats}. Includes {api_key_events} API Key events "
            f"and {logon_events} logon/logoff events, confirming administrative and "
            f"API actions are being recorded."
        )
    else:
        fail_reasons.append(
            "Audit log endpoint returned zero records, so no administrative or API "
            "actions could be confirmed as logged for this tenant."
        )
        recommendations.append(
            "Enable audit logging for Vision One administrative and API actions, "
            "or verify the API credential has access to the audit log feed."
        )

    result = {
        "isApiAuditLoggingEnabled": is_enabled,
        "totalAuditLogEntries": total,
        "apiKeyEventCount": api_key_events,
        "logonEventCount": logon_events,
        "otherAdminEventCount": other_admin_events,
    }

    input_summary = {
        "totalAuditLogEntries": total,
        "categoriesObserved": sorted([c for c in admin_categories if c]),
    }

    metadata = {
        "transformationId": "isApiAuditLoggingEnabled",
        "vendor": "Trend Micro XDR",
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
