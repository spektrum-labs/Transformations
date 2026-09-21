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


def parse_iso_datetime(s):
    if not s or not isinstance(s, str):
        return None
    try:
        s2 = s.replace("Z", "")
        if "T" in s2:
            date_part, time_part = s2.split("T")
        else:
            return None
        year, month, day = date_part.split("-")
        time_part = time_part.split("+")[0]
        hms = time_part.split(".")[0]
        h, mi, sec = hms.split(":")
        return datetime(int(year), int(month), int(day), int(h), int(mi), int(sec))
    except Exception:
        return None


def transform(input):
    data, validation = extract_input(input)
    data = data if isinstance(data, (dict, list)) else {}

    if isinstance(data, list):
        invites = data
    elif isinstance(data, dict):
        invites = data.get("data") or []
    else:
        invites = []

    if not isinstance(invites, list):
        invites = []

    now = datetime.utcnow()

    stale_pending = []
    pending_total = 0
    for inv in invites:
        if not isinstance(inv, dict):
            continue
        status = inv.get("status") or ""
        if status == "pending":
            pending_total = pending_total + 1
            expires_at = parse_iso_datetime(inv.get("expires_at"))
            if expires_at is not None and expires_at < now:
                stale_pending.append(inv)

    stale_count = len(stale_pending)

    input_summary = {
        "totalInvites": len(invites),
        "pendingInvites": pending_total,
        "stalePendingInvites": stale_count,
    }

    if stale_count > 0:
        ids = [i.get("id") for i in stale_pending[:5] if isinstance(i, dict)]
        pass_reasons = [
            f"Found {stale_count} invite(s) with status='pending' whose expires_at has passed "
            f"(examples: {ids}), out of {pending_total} total pending invites and {len(invites)} total invites."
        ]
        fail_reasons = []
        recommendations = [
            "Revoke or resend the stale pending invites identified so unclaimed access grants do not remain open indefinitely."
        ]
    else:
        pass_reasons = [
            f"No stale pending invites found. {pending_total} invite(s) currently pending, none past their expires_at window, "
            f"out of {len(invites)} total invites."
        ]
        fail_reasons = []
        recommendations = []

    result = {
        "pendingOrgInvitesCount": stale_count,
        "totalPendingInvites": pending_total,
        "totalInvites": len(invites),
    }

    return create_response(
        result=result,
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary=input_summary,
        metadata={
            "transformationId": "pendingOrgInvitesCount",
            "vendor": "Anthropic Claude Developer Platform Claude API",
            "category": "artificial-intelligence",
        },
    )
