"""
Transformation: requiredCoveragePercentage
Red Canary MDR: the share of the tenant's live endpoints that Red Canary itself reports as
monitored, as a whole-number percentage (rounded down, so it never overstates coverage).

    coverage = monitored endpoints / total endpoints * 100

Numerator:   endpoints whose attributes.monitoring_status is "monitored"
Denominator: every endpoint in the complete getEndpoints census that is not decommissioned

Both come from GET /openapi/v3/endpoints. The threshold lives in the bundle criterion, not here.

2026-10-02: the previous version divided the number of listed endpoints by an "expected fleet"
it looked for in the response body. The body never carries one, so the expected count fell back
to the listed count and every tenant read 100%, whatever monitoring_status said (Ethico 107 of
194 monitored, Gohlke 18 of 21, Kingsmen 5 of 10 all read 100%). It now reads monitoring_status.

A read that cannot show the whole census -- empty, an error, cut short, or records that do not
report a monitoring_status -- is Unevaluated with the reason: never 100% and never 0%.
"""
import json
from datetime import datetime


def extract_input(input_data):
    """Extract data and validation from input, handling enriched + legacy formats."""
    if isinstance(input_data, dict) and "data" in input_data and "validation" in input_data:
        return input_data["data"], input_data["validation"]
    data = input_data
    if isinstance(data, dict):
        wrapper_keys = ["api_response", "response", "result", "apiResponse", "Output"]
        for attempt in range(3):
            unwrapped = False
            for key in wrapper_keys:
                if key in data and isinstance(data.get(key), dict):
                    data = data[key]
                    unwrapped = True
                    break
            if not unwrapped:
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


# ---- fail-closed guard (2026-10-01) ------------------------------------------------------------
# A read that does not show a measured, complete endpoint census proves nothing either way, so the
# criterion is returned as None with dataCollection.status "error". Token-Service reads that as
# Unevaluated: never a pass and never a finding. It covers a missing or empty body, a vendor or
# platform error envelope, a payload this transformation does not recognise, a read that came back
# with zero endpoints, and a read shorter than the census it reports (truncated).
#
# Why zero endpoints is not a measurement: the integration pages GET /openapi/v3/endpoints, and
# when Red Canary rate-limits a page part-way through (HTTP 429 after the retries) the platform
# hands this transformation an empty body with no error on it. Zero endpoints from that read is a
# failed read, not a tenant with MDR switched off, and a tenant that really runs no endpoints has
# nothing for an endpoint check to measure.

#: the integration reads at most 100 pages of Red Canary's 50-endpoint pages; a census this long may
#: have stopped at that cap rather than at the last endpoint
ENDPOINT_READ_CAP = 5000

#: attributes a Red Canary v3 endpoint record carries; one of them marks a record as an endpoint
ENDPOINT_FIELDS = ("monitoring_status", "endpoint_status", "is_decommissioned", "hostname",
                   "display_identifier", "platform", "registration_time", "last_checkin_time")


def parse_body(data):
    """A JSON string or bytes body parsed; anything else unchanged. Unparseable text stays text."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except Exception:
            return data
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return data
    return data


def error_problem(data):
    """Describe why `data` is a vendor or platform error rather than evidence, or return None."""
    if data is None:
        return "Red Canary returned no body"
    if isinstance(data, (str, bytes)):
        return "Red Canary returned a body that is not JSON"
    if not isinstance(data, dict):
        return None
    for name in ("statusCode", "status_code", "httpStatus", "vendorStatus"):
        code = data.get(name)
        if isinstance(code, str) and code.strip().isdigit():
            code = int(code.strip())
        if isinstance(code, int) and not isinstance(code, bool) and code >= 400:
            return "Red Canary returned HTTP " + str(code)
    err = data.get("error") or data.get("errors") or data.get("vendorError")
    if err:
        if isinstance(err, list):
            err = err[0]
        if isinstance(err, dict):
            err = err.get("message") or err.get("detail") or err.get("title") or err.get("type") or "error"
        return "Red Canary returned an error: " + str(err)[:200]
    if str(data.get("status", "")).strip().lower() == "error":
        return "the integration reported an error status"
    return None


def as_count(value):
    """An integer count from an int or a numeric string (Red Canary sends counts as strings)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip() if value is not None else ""
    if text.isdigit():
        return int(text)
    return None


def is_endpoint_record(item):
    """True when `item` reads as a Red Canary endpoint (v3 nests its fields under attributes)."""
    if not isinstance(item, dict):
        return False
    if str(item.get("type") or "").strip().lower() == "endpoint":
        return True
    attrs = item.get("attributes")
    fields = attrs if isinstance(attrs, dict) else item
    for name in ENDPOINT_FIELDS:
        if name in fields:
            return True
    return False


def endpoint_census(data):
    """(endpoints, meta, problem): the records of a complete endpoints read, or why there are none.

    Token-Service hands a legacy transformation the drilled endpoint LIST; the enveloped
    {"meta", "links", "data"} body is read as well.
    """
    problem = error_problem(data)
    if problem:
        return None, {}, problem
    meta = {}
    endpoints = None
    if isinstance(data, list):
        endpoints = data
    elif isinstance(data, dict):
        for name in ("data", "endpoints", "value"):
            if isinstance(data.get(name), list):
                endpoints = data.get(name)
                break
        if isinstance(data.get("meta"), dict):
            meta = data.get("meta")
    if endpoints is None:
        return None, meta, ("The response carries no endpoints collection: the endpoints read "
                            "cannot be shown to have run, so nothing was measured")
    if len(endpoints) == 0:
        return None, meta, ("Red Canary returned 0 endpoints. A read that fails part-way returns an "
                            "empty body, so zero endpoints is not evidence either way")
    recognised = 0
    for ep in endpoints:
        if is_endpoint_record(ep):
            recognised = recognised + 1
    if recognised == 0:
        return None, meta, ("The response carries no Red Canary endpoint records: nothing was "
                            "measured")
    if str(meta.get("truncated") or "").strip().lower() == "true":
        return None, meta, ("The endpoints read stopped at the page cap: the census is incomplete, "
                            "so nothing was measured")
    reported = as_count(meta.get("total_items"))
    if reported is not None and reported > len(endpoints):
        return None, meta, ("The endpoints read is incomplete: Red Canary reports " + str(reported)
                            + " endpoint(s) and " + str(len(endpoints)) + " were returned")
    if len(endpoints) >= ENDPOINT_READ_CAP:
        return None, meta, ("The endpoints read returned " + str(len(endpoints)) + " endpoints, "
                            "the integration's page cap: the census may be incomplete")
    return endpoints, meta, None


def unevaluated(keys, problem, validation=None, input_summary=None, transformation_errors=None):
    """Every key as None plus a dataCollection error: reads Unevaluated, never True or False."""
    result = {}
    for key in keys:
        result[key] = None
    return create_response(
        result=result,
        validation=validation,
        fail_reasons=[problem],
        api_errors=[problem],
        transformation_errors=transformation_errors,
        input_summary=input_summary,
    )


def coverage_census(endpoints):
    """(monitored, total, decommissioned, problem) over a complete endpoint census.

    Red Canary v3 nests fields under attributes; a flat record is read the same way. Booleans
    arrive as strings ("True"/"False"). A live endpoint that reports no monitoring_status makes
    the census partial: coverage cannot be stated, so problem names how many are missing.
    """
    monitored = 0
    total = 0
    decommissioned = 0
    unreadable = 0
    no_status = 0
    for ep in endpoints:
        if not is_endpoint_record(ep):
            unreadable = unreadable + 1
            continue
        attrs = ep.get("attributes")
        fields = attrs if isinstance(attrs, dict) else ep
        if str(fields.get("is_decommissioned")).strip().lower() == "true":
            decommissioned = decommissioned + 1
            continue
        total = total + 1
        status = str(fields.get("monitoring_status") or "").strip().lower()
        if not status:
            no_status = no_status + 1
        elif status == "monitored":
            monitored = monitored + 1
    if unreadable:
        return monitored, total, decommissioned, (
            str(unreadable) + " of " + str(len(endpoints)) + " records in the endpoints read are "
            "not Red Canary endpoints: the census is partial, so coverage was not measured")
    if total == 0:
        return monitored, total, decommissioned, (
            "Every endpoint Red Canary returned (" + str(decommissioned) + ") is decommissioned: "
            "there is no live endpoint to measure coverage over")
    if no_status:
        return monitored, total, decommissioned, (
            str(no_status) + " of " + str(total) + " live endpoint(s) report no monitoring_status: "
            "the census is partial, so coverage was not measured")
    return monitored, total, decommissioned, None


def transform(input):
    keys = ["requiredCoveragePercentage"]
    empty_summary = {"monitoredEndpoints": None, "totalEndpoints": None}
    try:
        data, validation = extract_input(parse_body(input))
        if isinstance(validation, dict) and validation.get("status") == "failed":
            return unevaluated(keys, "Input validation failed: nothing was measured", validation)
        endpoints, meta, problem = endpoint_census(data)
        if problem:
            return unevaluated(keys, problem, validation, input_summary=empty_summary)
        monitored, total, decommissioned, problem = coverage_census(endpoints)
        if problem:
            return unevaluated(keys, problem, validation, input_summary={
                "monitoredEndpoints": monitored, "totalEndpoints": total,
                "decommissionedEndpoints": decommissioned})
        return measure(monitored, total, decommissioned, meta, validation)
    except Exception as e:
        message = "Transformation error: " + str(e)[:200]
        return unevaluated(keys, message, {"status": "error", "errors": [], "warnings": []},
                           transformation_errors=[message])


def measure(monitored, total, decommissioned, meta, validation):
    """The whole-number coverage from a complete census with total > 0 (see coverage_census)."""
    coverage_pct = (monitored * 100) // total
    unmonitored = total - monitored
    summary = (str(monitored) + " of " + str(total) + " live endpoint(s) are monitored by Red Canary ("
               + str(coverage_pct) + "%)")
    pass_reasons = []
    fail_reasons = []
    recommendations = []
    if unmonitored == 0:
        pass_reasons.append(summary + ".")
    else:
        fail_reasons.append(summary + "; " + str(unmonitored) + " are unmonitored.")
        recommendations.append(
            "Return the unmonitored endpoints to monitoring in the Red Canary portal (Endpoints, "
            "filter monitoring status: unmonitored), or decommission those no longer in service.")
    return create_response(
        result={
            "requiredCoveragePercentage": coverage_pct,
            "monitoredEndpoints": monitored,
            "unmonitoredEndpoints": unmonitored,
            "totalEndpoints": total,
            "decommissionedEndpoints": decommissioned,
        },
        validation=validation,
        pass_reasons=pass_reasons,
        fail_reasons=fail_reasons,
        recommendations=recommendations,
        input_summary={
            "totalItems": meta.get("total_items"),
            "monitoredEndpoints": monitored,
            "totalEndpoints": total,
            "decommissionedEndpoints": decommissioned,
        },
        metadata={
            "transformationId": "requiredCoveragePercentage",
            "vendor": "Red Canary",
            "category": "mdr",
        },
    )
