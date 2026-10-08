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


def transform_evidence(input):
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
        # login attempts always carry an "mfa" key (true or false); only mfa true is MFA activity
        has_mfa_field = ev.get("mfa") is True
        has_mfa_meta = bool(ev.get("mfa_meta"))
        has_auth_mfa_context = bool(ev.get("auth_mfa_context"))
        is_mfa_event_type = "mfa" in event_type.lower()

        if has_mfa_field or has_mfa_meta or has_auth_mfa_context or is_mfa_event_type:
            mfa_event_count = mfa_event_count + 1
            if is_mfa_event_type:
                sample_event_type = event_type
                mfa_event_types[event_type] = mfa_event_types.get(event_type, 0) + 1


    if mfa_event_count == 0 and total_events >= PAGE_LIMIT:
        return unevaluated(
            "Read " + str(total_events) + " Directory Insights events, the per-query cap, and none matched; "
            "older events in the window were not read, so absence is not scored.", validation)
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


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud Directory Insights event list proves nothing, so the key is returned as
# None with dataCollection.status "error": the check reads Unevaluated, never a pass and never a fail.
# IS searchDirectoryAuditEvents asks for PAGE_LIMIT rows (JumpCloud's per-query maximum) and cannot follow
# the X-Search_after header, so a read of PAGE_LIMIT rows may be missing older events in the window.
PAGE_LIMIT = 10000


def unevaluated(problem, validation):
    return create_response(
        result={"isMFALoggingEnabled": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "isMFALoggingEnabled", "vendor": "JumpCloud",
                  "category": "identity-and-access-management"},
    )


def event_list(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("apiResponse", "data", "results"):
            if isinstance(data.get(k), list):
                return data[k]
    return None


def evidence_problem(data):
    events = event_list(data)
    if events is None:
        return "No JumpCloud Directory Insights event list in the response; nothing to evaluate."
    if len(events) == 0:
        return ("JumpCloud returned no Directory Insights events for the window; an empty read cannot tell "
                "logging off from a failed or filtered query, so it is not scored.")
    for e in events:
        if not isinstance(e, dict) or not e.get("event_type") or not e.get("timestamp"):
            return "The response items are not Directory Insights event records (event_type, timestamp)."
    return None


def transform(input):
    data, validation = extract_input(input)
    problem = evidence_problem(data)
    if problem:
        return unevaluated(problem, validation)
    return transform_evidence(input)
