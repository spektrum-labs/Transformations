"""Transformation: hasAuthenticationLogAPIAccess"""
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

    # Authentication events only: user/admin login attempts and MFA or auth events. "password" matched
    # user_password_warning_email, "sso" matched "association_change", and "session" matched nothing
    # authentication-specific. The query reads service "directory", which carries no SSO events.
    auth_event_types = (
        "login", "auth", "mfa"
    )

    auth_events = []
    for e in events:
        if not isinstance(e, dict):
            continue
        et = e.get("event_type") or ""
        et_lower = et.lower() if isinstance(et, str) else ""
        if any(k in et_lower for k in auth_event_types):
            auth_events.append(e)

    auth_events_with_fields = [
        e for e in auth_events
        if ("success" in e) or ("auth_method" in e) or ("mfa" in e)
    ]


    if len(auth_events) == 0 and total_events >= PAGE_LIMIT:
        return unevaluated(
            "Read " + str(total_events) + " Directory Insights events, the per-query cap, and none matched; "
            "older events in the window were not read, so absence is not scored.", validation)
    has_access = total_events > 0 and len(auth_events) > 0

    input_summary = {
        "totalEventsReturned": total_events,
        "authRelatedEventCount": len(auth_events),
        "authEventsWithAuthFields": len(auth_events_with_fields),
    }

    if has_access:
        sample_types = sorted(set(
            (e.get("event_type") for e in auth_events[:5] if isinstance(e, dict))
        ))
        pass_reasons = [
            f"POST to /insights/directory/v1/events returned {total_events} directory events, "
            f"including {len(auth_events)} authentication-related events (event_type values such as {sample_types}) "
            f"with fields like success/auth_method/mfa present on {len(auth_events_with_fields)} of them, "
            "demonstrating programmatic API access to authentication logs."
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            f"The searchDirectoryAuditEvents call returned {total_events} events, of which "
            f"{len(auth_events)} were authentication-related (event_type containing login/auth/mfa)."
        ]
        recommendations = [
            "Verify the API key has permission to read Directory Insights events and that authentication "
            "activity has occurred within the queried time window."
        ]

    result = {
        "hasAuthenticationLogAPIAccess": has_access,
        "totalEventsReturned": total_events,
        "authRelatedEventCount": len(auth_events),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "hasAuthenticationLogAPIAccess",
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
        result={"hasAuthenticationLogAPIAccess": None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": "hasAuthenticationLogAPIAccess", "vendor": "JumpCloud",
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
