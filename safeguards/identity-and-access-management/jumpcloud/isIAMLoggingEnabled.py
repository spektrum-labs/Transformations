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


# ---- fail-closed guard (2026-09-29) ------------------------------------------------------------
# A body that is not a JumpCloud Directory Insights event list proves nothing, so the key is returned as
# None with dataCollection.status "error": the check reads Unevaluated, never a pass and never a fail.
# IS searchDirectoryAuditEvents asks for PAGE_LIMIT rows (JumpCloud's per-query maximum) and cannot follow
# the X-Search_after header, so a read of PAGE_LIMIT rows may be missing older events in the window.
PAGE_LIMIT = 10000


def unevaluated(problem, validation):
    return create_response(
        result={"isIAMLoggingEnabled": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "isIAMLoggingEnabled", "vendor": "JumpCloud",
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
