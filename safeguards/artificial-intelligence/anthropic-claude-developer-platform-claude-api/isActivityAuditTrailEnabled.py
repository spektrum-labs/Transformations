
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
        items = data.get("data") or []
    else:
        items = []

    if not isinstance(items, list):
        items = []

    total_events = len(items)

    security_relevant_types = set()
    admin_action_count = 0
    login_or_access_count = 0
    distinct_actor_types = set()

    for ev in items:
        if not isinstance(ev, dict):
            continue
        ev_type = ev.get("type") or ""
        if ev_type:
            security_relevant_types.add(ev_type)
        actor = ev.get("actor") or {}
        if isinstance(actor, dict):
            actor_type = actor.get("type") or ""
            if actor_type:
                distinct_actor_types.add(actor_type)
        if "invite" in ev_type or "role" in ev_type or "key" in ev_type or "member" in ev_type or "org_" in ev_type:
            admin_action_count = admin_action_count + 1
        if "accessed" in ev_type or "login" in ev_type or "signed_in" in ev_type:
            login_or_access_count = login_or_access_count + 1

    is_enabled = total_events > 0

    input_summary = {
        "totalActivityEvents": total_events,
        "distinctEventTypes": len(security_relevant_types),
        "adminActionEvents": admin_action_count,
        "accessEvents": login_or_access_count,
        "distinctActorTypes": len(distinct_actor_types),
    }

    if is_enabled:
        sample_types = list(security_relevant_types)[:5]
        pass_reasons = [
            f"Compliance API activity feed (/v1/compliance/activities) returned {total_events} audit events for the organization.",
            f"Observed {len(security_relevant_types)} distinct event types including: {', '.join(sample_types)}.",
            f"{admin_action_count} events reflect administrative actions (invites, roles, keys, org membership) and {login_or_access_count} reflect API/compliance access events.",
        ]
        fail_reasons = []
        recommendations = []
    else:
        pass_reasons = []
        fail_reasons = [
            "The Compliance API activity feed returned zero events, so no audit trail of logins or administrative actions is currently observable for this organization.",
        ]
        recommendations = [
            "Verify the Admin API key has the read:compliance_activities scope and that compliance activity logging is enabled for the organization, then confirm events populate over time.",
        ]

    result = {
        "isActivityAuditTrailEnabled": is_enabled,
        "totalActivityEvents": total_events,
        "adminActionEvents": admin_action_count,
        "accessEvents": login_or_access_count,
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "isActivityAuditTrailEnabled",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "Artificial Intelligence",
        },
    )
