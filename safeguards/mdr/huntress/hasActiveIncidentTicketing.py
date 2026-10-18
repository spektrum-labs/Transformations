"""Transformation: hasActiveIncidentTicketing - Huntress Managed EDR (MDR), Huntress REST API v1, GET /v1/incident_reports.

True only when a Huntress incident report carries a PSA ticket id (psa_ticket_eids), which is Huntress's own record that the
incident was routed to the connected ticketing system. A ticket on any one report proves routing, even on a partial read.
False only on a complete read of at least one report where none carries a ticket. No reports, an error body or a partial read
without a ticket is not measured (None): there is nothing to prove routing from.
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


VENDOR = "Huntress"


def not_measured(key, problem, validation):
    return create_response(
        result={key: None},
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )


def has_ticket(report):
    ids = report.get("psa_ticket_eids")
    if not isinstance(ids, list):
        return False
    for t in ids:
        if isinstance(t, (str, int)) and not isinstance(t, bool) and str(t).strip() not in ("", "None", "null"):
            return True
    return False


def read_reports(input):
    """(reports, complete, problem). A partial read still returns what it holds, with complete False."""
    box, problem = find_key(raw_body(input), "incident_reports")
    if problem is not None:
        return None, False, "Huntress returned an error instead of an incident report list: " + problem
    if box is None or not isinstance(box.get("incident_reports"), list):
        return None, False, "No Huntress incident report list in the response; nothing to evaluate."
    reports = [r for r in box["incident_reports"] if isinstance(r, dict)]
    if len(reports) != len(box["incident_reports"]):
        return None, False, "The incident report list holds entries that are not incident reports, so it cannot be scored."
    pagination = box.get("pagination")
    complete = isinstance(pagination, dict)
    if complete and pagination.get("truncated"):
        complete = False
    if complete and str(pagination.get("next_page_token") or "").strip() not in ("", "None", "null"):
        complete = False
    return reports, complete, None


def transform(input):
    key = "hasActiveIncidentTicketing"
    validation = extract_validation(input)
    reports, complete, problem = read_reports(input)
    if problem is not None:
        return not_measured(key, problem, validation)
    if not reports:
        return not_measured(key, "Huntress returned no incident reports, so there is no incident to show routed to a ticket.", validation)
    ticketed = [r for r in reports if has_ticket(r)]
    if ticketed:
        text = (str(len(ticketed)) + " of " + str(len(reports)) + " Huntress incident reports read carry a PSA ticket id, "
                "so incidents are routed to a connected ticketing system.")
        ok = True
    elif complete:
        text = ("None of the " + str(len(reports)) + " Huntress incident reports carries a PSA ticket id, so incidents "
                "are not routed to a ticketing system.")
        ok = False
    else:
        return not_measured(key, "Only part of the incident report list was read and none of it carries a PSA ticket id; "
                            "a partial read cannot show that no ticket is created.", validation)
    return create_response(
        result={key: ok, "incidentReportsRead": len(reports), "ticketedIncidentReports": len(ticketed)},
        validation=validation,
        pass_reasons=[text] if ok else [],
        fail_reasons=[] if ok else [text],
        recommendations=[] if ok else ["Connect Huntress to the PSA or ticketing system in the Huntress integrations settings."],
        input_summary={"incidentReportsRead": len(reports), "ticketedIncidentReports": len(ticketed), "completeRead": complete},
        metadata={"transformationId": key, "vendor": VENDOR, "category": "mdr"},
    )
