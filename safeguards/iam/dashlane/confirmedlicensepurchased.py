"""Transformation: confirmedLicensePurchased - Dashlane (password manager), Public API POST /public/teams/Status.

True only when the team status reports at least one active seat (data.seats.active), which is Dashlane's own record of
a team with a seat in use. A reply that carries no seats object, an error, or a rejected key is not measured (None). A
team that reports no active seat is False.
"""
import json
from datetime import datetime


def extract_validation(input_data):
    if isinstance(input_data, dict) and "validation" in input_data and isinstance(input_data["validation"], dict):
        return input_data["validation"]
    return {"status": "unknown", "errors": [], "warnings": ["Legacy input format - no schema validation performed"]}


def create_response(result, validation=None, pass_reasons=None, fail_reasons=None,
                    recommendations=None, input_summary=None, metadata=None,
                    transformation_errors=None, api_errors=None, additional_findings=None):
    """Standardized 5-section transformation response."""
    if validation is None:
        validation = {"status": "unknown", "errors": [], "warnings": []}
    api_err_list = api_errors or []
    transform_err_list = transformation_errors or []
    response_metadata = {"evaluatedAt": datetime.utcnow().isoformat() + "Z", "schemaVersion": "2.0"}
    if metadata:
        response_metadata.update(metadata)
    return {
        "transformedResponse": result,
        "additionalInfo": {
            "dataCollection": {"status": "error" if api_err_list else "success", "errors": api_err_list},
            "validation": {
                "status": validation.get("status", "unknown"),
                "errors": validation.get("errors", []),
                "warnings": validation.get("warnings", []),
            },
            "transformation": {
                "status": "error" if transform_err_list else "success",
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


WRAPPERS = ["result", "response", "apiResponse", "api_response", "Output", "data", "_response_data"]
VENDOR = "Dashlane"


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error, truncated) for the first dict, through any wrapper, that carries key `wanted`.

    `truncated` is True when Integration-Service marked the read partial (paginationTruncated / truncated) on any
    wrapper level it passed through.
    """
    cur = obj
    truncated = False
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None, truncated
        if not isinstance(cur, dict):
            return None, None, truncated
        if cur.get("paginationTruncated") is True or cur.get("truncated") is True:
            truncated = True
        if wanted in cur:
            return cur, None, truncated
        problem = error_in(cur)
        if problem is not None:
            return None, problem, truncated
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None, truncated
        cur = nxt
    return None, None, truncated


def raw_body(input):
    # A {data, validation} envelope means Token-Service passed the undrilled response.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "iam"},
    )


def count_of(seats, name):
    value = seats.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def transform(input):
    key = "confirmedLicensePurchased"
    validation = extract_validation(input)
    box, problem, truncated = find_key(raw_body(input), "seats")
    if problem is not None:
        return not_measured(key, "Dashlane returned an error instead of the team status: " + problem, validation)
    seats = box.get("seats") if box is not None else None
    if not isinstance(seats, dict):
        return not_measured(key, "No seats object in the Dashlane team status; the licence cannot be read.", validation)
    active = count_of(seats, "active")
    if active is None:
        return not_measured(key, "The Dashlane team status carries no active seat count.", validation)
    pending = count_of(seats, "pending")
    remaining = count_of(seats, "remaining")
    ok = active >= 1
    text = ("The Dashlane team has " + str(active) + " active seat(s)" + (" and " + str(pending) + " pending" if pending is not None else "") + "."
            if ok else "The Dashlane team status reports no active seat, so no licence is in use.")
    return create_response(
        result={key: ok, "activeSeats": active, "pendingSeats": pending, "remainingSeats": remaining},
        validation=validation,
        pass_reasons=[text] if ok else [],
        fail_reasons=[] if ok else [text],
        recommendations=[] if ok else ["Invite members to the Dashlane team and confirm the plan is active."],
        input_summary={"activeSeats": active},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "iam"},
    )
