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
    mfa_event_count = 0
    mfa_event_types = {}
    sample_event_type = None

    for ev in events:
        if not isinstance(ev, dict):
            continue
        event_type = ev.get("event_type") or ""
        has_mfa_field = "mfa" in ev
        has_mfa_meta = bool(ev.get("mfa_meta"))
        has_auth_mfa_context = bool(ev.get("auth_mfa_context"))
        is_mfa_event_type = "mfa" in event_type.lower()

        if has_mfa_field or has_mfa_meta or has_auth_mfa_context or is_mfa_event_type:
            mfa_event_count = mfa_event_count + 1
            if is_mfa_event_type:
                sample_event_type = event_type
                mfa_event_types[event_type] = mfa_event_types.get(event_type, 0) + 1

    is_mfa_logging_enabled = mfa_event_count > 0

    input_summary = {
        "totalEvents": total_events,
        "mfaRelatedEvents": mfa_event_count,
    }

    if is_mfa_logging_enabled:
        pass_reasons = [
            f"Directory Insights events feed returned {total_events} records; {mfa_event_count} of them carry MFA-related fields (mfa/mfa_meta/auth_mfa_context) or MFA-related event_type values (e.g. {sample_event_type or 'user_mfa_*'}), demonstrating MFA activity is captured in the audit log."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"Of {total_events} directory audit events returned, none carried an 'mfa', 'mfa_meta', or 'auth_mfa_context' field nor an MFA-related event_type, indicating MFA activity is not present in this audit log sample."
        ]
        recommendations = [
            "Verify that MFA is enabled for users and that Directory Insights is configured to capture MFA verification/enrollment events (event types such as user_mfa_verification_attempt)."
        ]

    result = {
        "isMFALoggingEnabled": is_mfa_logging_enabled,
        "totalEvents": total_events,
        "mfaRelatedEvents": mfa_event_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isMFALoggingEnabled",
            "vendor": "JumpCloud",
            "category": "identity-and-access-management",
        },
    )
