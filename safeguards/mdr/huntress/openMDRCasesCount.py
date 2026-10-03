"""Transformation: openMDRCasesCount - Huntress Managed EDR (MDR), Huntress REST API v1. Not measured (None) on any body that proves nothing."""
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


def error_in(cur):
    """A short error string when a vendor/IS error body is in hand, else None."""
    if cur.get("errors") or cur.get("error") is True or isinstance(cur.get("error"), (str, dict)):
        detail = cur.get("errors") or cur.get("error") or cur.get("message") or "error"
        return json.dumps(detail)[:300]
    code = cur.get("status_code") or cur.get("statusCode") or cur.get("status")
    if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
        return "HTTP " + str(code) + ": " + json.dumps(cur.get("message") or cur.get("detail") or "")[:200]
    return None


def find_key(obj, wanted):
    """(container_dict, error) for the first dict, through any wrapper, that carries key `wanted`."""
    cur = obj
    for depth in range(8):
        if isinstance(cur, str):
            try:
                cur = json.loads(cur)
            except Exception:
                return None, None
        if not isinstance(cur, dict):
            return None, None
        if wanted in cur:
            return cur, None
        problem = error_in(cur)
        if problem is not None:
            return None, problem
        nxt = None
        for key in WRAPPERS:
            if isinstance(cur.get(key), (dict, str)):
                nxt = cur.get(key)
                break
        if nxt is None:
            return None, None
        cur = nxt
    return None, None


def raw_body(input):
    # input.get("data") makes Token-Service pass the undrilled response in a {data, validation}
    # envelope, so the pagination block stays visible and a partial read is caught.
    if isinstance(input, dict) and "validation" in input:
        return input.get("data")
    return input


def parse_time(text):
    """Naive-UTC datetime from an ISO-8601 string, or None."""
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        return datetime.fromisoformat(text[:19])
    except Exception:
        return None


def pct(part, whole):
    return round(100.0 * part / whole, 2) if whole else None


VENDOR = "Huntress"
STALE_DAYS = 15


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )


def complete_list(input, list_key, noun):
    """(items, None) for a complete Huntress list read, else (None, problem).

    Complete means: the `list_key` array beside Huntress's pagination block, no
    next_page_token left, and no Integration-Service `truncated` marker (maxPages hit).
    """
    box, problem = find_key(raw_body(input), list_key)
    if problem is not None:
        return None, "Huntress returned an error instead of a " + noun + " list: " + problem
    if box is None or not isinstance(box.get(list_key), list):
        return None, "No Huntress " + noun + " list in the response; nothing to evaluate."
    pagination = box.get("pagination")
    if not isinstance(pagination, dict):
        return None, "The " + noun + " list carries no pagination block, so a complete read cannot be shown."
    items = [i for i in box[list_key] if isinstance(i, dict)]
    if pagination.get("truncated"):
        return None, "Read stopped at the page limit (" + str(len(items)) + " " + noun + "s); a partial read is not scored."
    if str(pagination.get("next_page_token") or "").strip() not in ("", "None", "null"):
        return None, "Only part of the " + noun + " list was read (more pages remain); a partial read is not scored."
    return items, None


def agent_windows(agents):
    """(fresh, stale, undated) agents judged against the newest last_callback_at in the response."""
    dated = [(a, parse_time(a.get("last_callback_at"))) for a in agents]
    times = [t for a, t in dated if t is not None]
    if not times:
        return [], [], [a for a, t in dated]
    newest = max(times)
    fresh = [a for a, t in dated if t is not None and (newest - t).days <= STALE_DAYS]
    stale = [a for a, t in dated if t is not None and (newest - t).days > STALE_DAYS]
    undated = [a for a, t in dated if t is None]
    return fresh, stale, undated


def transform(input):
    key = "openMDRCasesCount"
    validation = extract_validation(input)
    reports, problem = complete_list(input, "incident_reports", "incident report")
    if problem is not None:
        return not_measured(key, problem, validation)
    open_reports = [r for r in reports if str(r.get("status") or "").lower() == "sent"]
    if len(open_reports) != len(reports):
        # The method asks Huntress for status=sent only; anything else means the filter did not apply.
        return not_measured(key, "The incident report list holds reports not in status 'sent'; the status filter did not apply, so the count is not scored.", validation)
    by_severity = {"critical": 0, "high": 0, "low": 0}
    for r in open_reports:
        sev = str(r.get("severity") or "").lower()
        if sev in by_severity:
            by_severity[sev] = by_severity[sev] + 1
    count = len(open_reports)
    text = (str(count) + " Huntress incident report(s) are open (sent, not closed): " + str(by_severity["critical"])
            + " critical, " + str(by_severity["high"]) + " high, " + str(by_severity["low"]) + " low.")
    return create_response(
        result={key: count, "criticalOpenIncidents": by_severity["critical"], "highOpenIncidents": by_severity["high"]},
        validation=validation,
        pass_reasons=[text] if count == 0 else [],
        fail_reasons=[text] if count else [],
        recommendations=["Work the open Huntress incident reports to closure."] if count else [],
        input_summary={"openIncidentReports": count},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )
